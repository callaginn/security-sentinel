import net from 'net';
import tls from 'tls';
import { promises as dnsPromises } from 'dns';
import chalk from 'chalk';

/**
	Gets a single IP address for a hostname using dns.lookup (OS resolver).
	@param {string} hostname - The website domain name.
	@returns {Promise<string|null>} A promise that resolves to the IP address string or null on error.
*/
async function getIpAddresses(hostname) {
	let allAddresses = [];
	try {
		// Get all IPv4 addresses (A records)
		const addressesV4 = await dnsPromises.resolve4(hostname);
		allAddresses = [...addressesV4];
		
		return allAddresses;
	} catch (error) {
		// Handle errors during the primary (IPv4) lookup
		console.error(`Error resolving hostname ${hostname}:`, error.message);
		if (error.code === 'ENOTFOUND') {
			console.error(`Could not find DNS records for ${hostname}.`);
		} else if (error.code === 'ENODATA') {
			console.error(`DNS server responded, but no A records found for ${hostname}.`);
		}
		return [];
	}
}

// MySQL Service Exposed to the Internet
function testMySQLService(host, port = 3306) {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		socket.setTimeout(5000); // Timeout after 5 seconds

		socket.connect(port, host, () => {
			console.warn(chalk.red(`❌ MySQL service is exposed on ${host}:${port}`));
			socket.destroy();
			resolve(false);
		});

		socket.on('error', () => {
			console.log(chalk.green(`✅ MySQL service is not exposed on ${host}:${port}`));
			resolve(true);
		});

		socket.on('timeout', () => {
			console.log(chalk.green(`✅ MySQL service is not exposed on ${host}:${port}`));
			socket.destroy();
			resolve(true);
		});
	});
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
function testEmailServiceWithoutTLS(host, port = 25) {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		socket.setTimeout(5000);

		socket.connect(port, host, () => {
			socket.once('data', (data) => {
				const banner = data.toString();
				if (banner.includes('ESMTP') && !banner.includes('STARTTLS')) {
					console.warn(chalk.red(`❌ Email service on ${host}:${port} does not support SSL/TLS`));
					resolve(false);
				} else {
					console.log(chalk.green(`✅ Email service on ${host}:${port} supports SSL/TLS`));
					resolve(true);
				}
				socket.destroy();
			});
		});

		socket.on('error', () => {
			console.log(chalk.green(`✅ Email service is not exposed on ${host}:${port}`));
			resolve(true);
		});

		socket.on('timeout', () => {
			console.log(chalk.green(`✅ Email service is not exposed on ${host}:${port}`));
			socket.destroy();
			resolve(true);
		});
	});
}

// 4. OpenSSH Remote Code Execution Vulnerability (CVE-2024-6387)
function testOpenSSHVersion(host, port = 22) {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		socket.setTimeout(5000);

		socket.connect(port, host, () => {
			socket.once('data', (data) => {
				const banner = data.toString();
				const versionMatch = banner.match(/OpenSSH_([\d.]+)/);
				if (versionMatch) {
					const version = versionMatch[1];
					if (version === '8.9p1') {
						console.warn(chalk.red(`❌ Vulnerable OpenSSH version detected on ${host}:${port}: ${version}`));
						resolve(false);
					} else {
						console.log(chalk.green(`✅ OpenSSH version on ${host}:${port} is secure: ${version}`));
						resolve(true);
					}
				} else {
					console.warn(chalk.yellow(`⚠ Unable to determine OpenSSH version on ${host}:${port}`));
					resolve(false);
				}
				socket.destroy();
			});
		});

		socket.on('error', () => {
			console.log(chalk.green(`✅ SSH service is not exposed on ${host}:${port}`));
			resolve(true);
		});

		socket.on('timeout', () => {
			console.log(chalk.green(`✅ SSH service is not exposed on ${host}:${port}`));
			socket.destroy();
			resolve(true);
		});
	});
}

export {
	getIpAddresses,
	testMySQLService,
	testSelfSignedCertificate,
	testEmailServiceWithoutTLS,
	testOpenSSHVersion
};