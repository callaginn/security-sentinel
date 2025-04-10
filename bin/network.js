import net from 'net';
import tls from 'tls';
import { promises as dnsPromises } from 'dns';
import util from 'util';
import chalk from 'chalk';
import { queryVulnersAPI, parseVulnerabilities } from './vulners-api.js';
import { table } from 'table';

import {
	wrapText
} from './common.js';

// Function to get all IPv4 addresses for a given hostname
async function getIpAddresses(hostname) {
	let allAddresses = [];
	try {
		const addressesV4 = await dnsPromises.resolve4(hostname);
		allAddresses = [...addressesV4];
		
		return allAddresses;
	} catch (error) {
		console.error(`Error resolving hostname ${hostname}:`, error.message);
		if (error.code === 'ENOTFOUND') {
			console.error(`Could not find DNS records for ${hostname}.`);
		} else if (error.code === 'ENODATA') {
			console.error(`DNS server responded, but no A records found for ${hostname}.`);
		}
		return [];
	}
}


/*/ =======================================================================================
	MARK: Socket Functions
======================================================================================= */

// Function to get the banner from a host
export function getHostBanner(host, port) {
	return new Promise((resolve, reject) => {
		const socket = new net.Socket();
		socket.setTimeout(5000); // Timeout after 5 seconds
		
		socket.connect(port, host, () => {
			socket.once('data', (data) => {
				socket.destroy();
				resolve(data.toString());
			});
		});
		
		socket.on('error', (err) => {
			socket.destroy();
			reject(err);
		});
		
		socket.on('timeout', () => {
			socket.destroy();
			reject(new Error('Connection timed out'));
		});
	});
}

// Function to infer system details (OS and SSH software)
function inferSystemDetails(banner) {
	const vendor = {
		ubuntu: "canonical",
		debian: "debian",
		centos: "centos",
		enterprise_linux: "redhat",
		fedora: "fedora",
		alpine_linux: "alpine",
		amazon_linux: "amazon"
	};
	
	const systemDetails = {
		operating_system: {
			part: "o",
			vendor: "unknown",
			product: "unknown",
			version: "unknown"
		},
		software: []
	};
	
	// Infer operating system details
	for (const [product, vendorName] of Object.entries(vendor)) {
		if (banner.toLowerCase().includes(product)) {
			const versionMatch = banner.match(new RegExp(`${product}[-\\s]?([\\d.]+)`, "i"));
			systemDetails.operating_system = {
				part: "o",
				vendor: vendorName,
				product: product,
				version: versionMatch ? versionMatch[1] : "unknown"
			};
			break;
		}
	}
	
	// Infer SSH software details
	const sshSoftwareMatch = banner.match(/SSH-\d+\.\d+-(\S+)/);
	if (sshSoftwareMatch) {
		const [_, softwareDetails] = sshSoftwareMatch;
		const [product, version] = softwareDetails.split('_');
		systemDetails.software.push({
			part: "a",
			vendor: "openbsd",
			product: product.toLowerCase(),
			version: version
		});
	}
	
	return systemDetails;
}

// MySQL Service Exposed to the Internet
async function testMySQLService(host, port = 3306) {
	try {
		const banner = await getHostBanner(host, port);
		if (banner) {
			console.warn(chalk.red(`❌ MySQL service is exposed on ${host}:${port}`));
			return false;
		}
	} catch (error) {
		if (error.message.includes("Connection timed out") || error.message.includes("ECONNREFUSED")) {
			console.log(chalk.green(`✅ MySQL service is not exposed on ${host}:${port}`));
			return true;
		}
		console.error(chalk.red(`❌ Error connecting to ${host}:${port}: ${error.message}`));
	}
	return false;
}

// Self-Signed Certificate
function testSelfSignedCertificate(host, port = 443) {
	return new Promise((resolve) => {
		const options = { host, port, rejectUnauthorized: false };
		const socket = tls.connect(options, () => {
			const cert = socket.getPeerCertificate();
			if (cert.issuer && cert.issuer.CN === cert.subject.CN) {
				console.warn(chalk.red(`❌ Self-signed certificate detected on ${host}:${port}`));
				resolve(false);
			} else {
				console.log(chalk.green(`✅ Valid certificate detected on ${host}:${port}`));
				resolve(true);
			}
			socket.end();
		});

		socket.on('error', (err) => {
			console.error(chalk.red(`❌ Error connecting to ${host}:${port}: ${err.message}`));
			resolve(false);
		});
	});
}

// 3. Email Service Without SSL/TLS
async function testEmailServiceWithoutTLS(host, port = 25) {
	try {
		const banner = await getHostBanner(host, port);
		if (banner.includes('ESMTP') && !banner.includes('STARTTLS')) {
			console.warn(chalk.red(`❌ Email service on ${host}:${port} does not support SSL/TLS`));
			return false;
		} else {
			console.log(chalk.green(`✅ Email service on ${host}:${port} supports SSL/TLS`));
			return true;
		}
	} catch (error) {
		if (error.message.includes("Connection timed out") || error.message.includes("ECONNREFUSED")) {
			console.log(chalk.green(`✅ Email service is not exposed on ${host}:${port}`));
			return true;
		}
		console.error(chalk.red(`❌ Error connecting to ${host}:${port}: ${error.message}`));
	}
	return false;
}

// 4. Vulnerability Scanner using the Vulners API
async function testOpenSSHVersion(host, port = 22) {
	return new Promise(async (resolve) => {
		try {
			const banner = await getHostBanner(host, port);
			const systemDetails = inferSystemDetails(banner);
			
			const query = {
				software: systemDetails.software,
				operating_system: systemDetails.operating_system,
				fields: ["title", "short_description", "cvelist", "ai_score", "metrics"]
			};
			
			// console.log(util.inspect(query, { colors: true, depth: null }));
			
			// Query the Vulners API
			const result = await queryVulnersAPI(query);
			
			if (result && result.result) {
				const vulnerabilities = parseVulnerabilities(result);
				// console.log(util.inspect(vulnerabilities, { colors: true, depth: null }));
				
				const config = {
					border: {
						topBody: `─`,
						topJoin: `┬`,
						topLeft: `┌`,
						topRight: `┐`,
					
						bottomBody: `─`,
						bottomJoin: `┴`,
						bottomLeft: `└`,
						bottomRight: `┘`,
					
						bodyLeft: `│`,
						bodyRight: `│`,
						bodyJoin: `│`,
					
						joinBody: `─`,
						joinLeft: `├`,
						joinRight: `┤`,
						joinJoin: `┼`
					}
				};
				
				for (const key in config.border) {
					if (typeof config.border[key] === 'string') {
						config.border[key] = chalk.dim(config.border[key]);
					}
				}
				
				let headers = [
					'Title',
					'AI Score',
					'CVSS Score',
					'CVSS Severity'
				];
				
				const colors = {
					bg: {
						low: chalk.bold.bgGreen,
						medium: chalk.bold.bgYellow,
						high: chalk.bold.bgRed,
						critical: chalk.bold.bgRed
					},
					border: {
						low: chalk.green,
						medium: chalk.yellow,
						high: chalk.red,
						critical: chalk.red
					}
				};
				
				let data = [
					headers.map(header => chalk.bold(header))
				];
				
				for (const [severity, vulns] of Object.entries(vulnerabilities)) {
					if (vulns.length > 0) {
						const labelBackground = colors.bg[severity] || chalk.dim;
						const labelForeground = colors.border[severity] || chalk.reset;
						
						data.push(
							...vulns.map((vuln) => [
								vuln.title,
								vuln.ai_score?.value || 'N/A',
								vuln.cvss_score || 'N/A',
								labelForeground('') + labelBackground(vuln.cvss_severity) + labelForeground('')
							])
						);
					}
				}
				
				// console.log(util.inspect(data, { colors: true, depth: null }));
				console.log(table(data, config).trim());
				
				for (const [severity, vulns] of Object.entries(vulnerabilities)) {
					if (vulns.length > 0) {
						console.log(chalk.italic.yellow(`\nFound ${vulns.length} ${severity} severity vulnerabilities:`));
						
						vulns.forEach((vuln) => {
							vuln = wrapText(`- ${vuln.title}: ${vuln.description} (CVSS: ${vuln.cvss_score})`, 100, '');
							console.log(chalk.dim(vuln));
						});
					} else {
						console.log(chalk.green(`✅ No ${severity} severity vulnerabilities found for ${host}:${port}`));
					}
				}
			} else {
				console.error(chalk.red("❌ No valid response from Vulners API."));
			}
		} catch (error) {
			console.error(chalk.red(`❌ Error processing OpenSSH version for ${host}:${port}: ${error.message}`));
		} finally {
			resolve();
		}
	});
}

export {
	getIpAddresses,
	testMySQLService,
	testSelfSignedCertificate,
	testEmailServiceWithoutTLS,
	testOpenSSHVersion
};