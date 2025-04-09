import fetch from 'node-fetch';
import puppeteer from 'puppeteer';
import cookie from 'cookie';
import chalk from 'chalk';

import {
	wrapText
} from './common.js';

// Function to handle redirect chain and HTTPS tests
async function testRedirectChainAndHTTPS(url) {
	console.group('\n' + chalk.bold.cyan('Redirect Chain and HTTPS Tests'));
	const redirectChain = [];
	let currentUrl = url;
	let response;
	
	do {
		response = await fetch(currentUrl, { redirect: 'manual' });
		const location = response.headers.get('location');
		if (location) {
			redirectChain.push(location);
			currentUrl = new URL(location, currentUrl).href;
		} else {
			break;
		}
	} while (response.status >= 300 && response.status < 400);
	
	const hasHttpRedirect = redirectChain.some((redirectUrl) => redirectUrl.startsWith('http://'));
	if (hasHttpRedirect) {
		console.warn(chalk.red('❌ Redirect chain contains HTTP URLs:'));
		redirectChain.forEach((redirectUrl) => console.warn(chalk.red(`	${redirectUrl}`)));
	} else {
		console.log(chalk.green('✅ All redirects use HTTPS'));
	}
	
	if (!currentUrl.startsWith('https://')) {
		console.warn(chalk.red(`❌ Final URL is not served over HTTPS: ${currentUrl}`));
	} else {
		console.log(chalk.green('✅ Final URL is served over HTTPS'));
	}
	
	if (redirectChain.length > 0) {
		const firstRedirect = redirectChain[0];
		if (firstRedirect.startsWith('https://') && !firstRedirect.includes(new URL(url).hostname)) {
			console.warn(chalk.red('❌ Insecure HTTPS redirect pattern detected'));
		} else {
			console.log(chalk.green('✅ HTTPS redirect pattern is secure'));
		}
	}
	console.groupEnd();
}

// Function to handle security headers tests
async function testSecurityHeaders(response) {
	console.group('\n' + chalk.bold.cyan('Security Headers'));
	const referrerPolicy = response.headers.get('referrer-policy');
	if (!referrerPolicy) {
		console.warn(chalk.red('❌ Missing Referrer-Policy header'));
	} else if (!['strict-origin-when-cross-origin', 'same-origin', 'no-referrer'].includes(referrerPolicy)) {
		console.warn(chalk.red(`❌ Referrer-Policy is set to a less secure value: "${referrerPolicy}"`));
	} else {
		console.log(chalk.green('✅ Referrer-Policy is secure'));
	}
	
	const headers = response.headers;
	const xFrameOptions = headers.get('x-frame-options');
	if (!xFrameOptions) {
		console.warn(chalk.red('❌ Missing X-Frame-Options header'));
	} else if (!['SAMEORIGIN', 'DENY'].includes(xFrameOptions.toUpperCase())) {
		console.warn(chalk.red(`❌ X-Frame-Options is set to an insecure value: "${xFrameOptions}"`));
	} else {
		console.log(chalk.green('✅ X-Frame-Options is secure'));
	}
	
	const xContentTypeOptions = headers.get('x-content-type-options');
	if (!xContentTypeOptions) {
		console.warn(chalk.red('❌ Missing X-Content-Type-Options header'));
	} else if (xContentTypeOptions.toLowerCase() !== 'nosniff') {
		console.warn(chalk.red(`❌ X-Content-Type-Options is set to an insecure value: "${xContentTypeOptions}"`));
	} else {
		console.log(chalk.green('✅ X-Content-Type-Options is secure'));
	}
	
	const hsts = headers.get('strict-transport-security');
	if (!hsts) {
		console.warn(chalk.red('❌ Missing Strict-Transport-Security (HSTS) header'));
	} else if (!hsts.includes('max-age=31536000') || !hsts.includes('includeSubDomains')) {
		console.warn(chalk.red(`❌ HSTS header is not configured securely: "${hsts}"`));
	} else {
		console.log(chalk.green('✅ HSTS header is secure'));
	}
	console.groupEnd();
}

// Function to handle Content Security Policy (CSP) tests
async function testCSP(response) {
	console.group('\n' + chalk.bold.cyan('Content Security Policy (CSP)'));
	const csp = response.headers.get('content-security-policy');
	if (!csp) {
		console.warn(chalk.red('❌ Missing Content-Security-Policy header'));
	} else {
		if (!csp.includes("frame-ancestors 'self'") && !csp.includes("frame-ancestors 'none'")) {
			console.warn(chalk.red('❌ Content-Security-Policy does not include a secure frame-ancestors directive'));
		} else {
			console.log(chalk.green('✅ Content-Security-Policy frame-ancestors directive is secure'));
		}
		
		const hasBroadScriptSrc = !csp.includes("script-src 'self'") && !csp.includes('script-src');
		const hasBroadObjectSrc = !csp.includes("object-src 'self'") && !csp.includes('object-src');
		if (hasBroadScriptSrc) {
			console.warn(chalk.red('❌ Content-Security-Policy contains broad script-src directive'));
		}
		if (hasBroadObjectSrc) {
			console.warn(chalk.red('❌ Content-Security-Policy contains broad object-src directive'));
		}
		if (!hasBroadScriptSrc && !hasBroadObjectSrc) {
			console.log(chalk.green('✅ Content-Security-Policy script-src and object-src directives are secure'));
		}
		
		const hasUnsafeInline = csp.includes("'unsafe-inline'");
		const hasUnsafeEval = csp.includes("'unsafe-eval'");
		if (hasUnsafeInline) {
			console.warn(chalk.red('❌ Content-Security-Policy contains "unsafe-inline" directive'));
		}
		if (hasUnsafeEval) {
			console.warn(chalk.red('❌ Content-Security-Policy contains "unsafe-eval" directive'));
		}
		if (!hasUnsafeInline && !hasUnsafeEval) {
			console.log(chalk.green('✅ Content-Security-Policy does not contain unsafe directives'));
		}
	}
	console.groupEnd();
}

// Function to handle cookie tests
async function testCookies(response) {
	console.group('\n' + chalk.bold.cyan('Cookies'));
	const rawSetCookies = response.headers.raw()['set-cookie'] || [];
	if (rawSetCookies.length === 0) {
		console.warn(chalk.green('✅ No Set-Cookie headers found'));
	} else {
		let issues = false;
		rawSetCookies.forEach((header, index) => {
			const parsed = cookie.parse(header);
			const flags = header.toLowerCase();
			
			const name = Object.keys(parsed)[0] || `Cookie ${index + 1}`;
			const isHttpOnly = flags.includes('httponly');
			const isSecure = flags.includes('secure');
			
			if (!isHttpOnly) {
				console.warn(chalk.red(`❌ Cookie "${name}" is missing HttpOnly flag`));
				issues = true;
			}
			
			if (!isSecure) {
				console.warn(chalk.red(`❌ Cookie "${name}" is missing Secure flag`));
				issues = true;
			}
		});
		
		if (!issues) {
			console.log(chalk.green('✅ All session cookies have HttpOnly and Secure flags'));
		}
	}
	console.groupEnd();
}

// Function to handle browser logs
async function testBrowserLogs(url) {
	console.group('\n' + chalk.bold.cyan('Browser Logs'));
	const browser = await puppeteer.launch({ headless: 'new' });
	const page = await browser.newPage();
	
	const messages = [];
	page.on('console', (msg) => {
		const type = msg.type();
		if (['log', 'debug', 'info', 'warn', 'error'].includes(type)) {
			messages.push({ type, text: msg.text() });
		}
	});
	
	try {
		await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
	} catch (err) {
		console.error(chalk.red(`❌ Puppeteer error loading page: ${err.message}`));
	}
	
	if (messages.length > 0) {
		console.warn(chalk.red('❌ Visible browser logs detected:'));
		messages.forEach((msg) => {
			const wrappedLine = wrapText(`	[${msg.type}] ${msg.text}`, 80, '	');
			console.warn(chalk.dim(wrappedLine));
		});
	} else {
		console.log(chalk.green('✅ No visible browser logs detected'));
	}
	
	await browser.close();
	console.groupEnd();
}

export {
	testRedirectChainAndHTTPS,
	testSecurityHeaders,
	testCSP,
	testCookies,
	testBrowserLogs
};