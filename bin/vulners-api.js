import fetch from 'node-fetch';

// 4. OpenSSH Vulnerability Scanner using the Vulners API
async function queryVulnersAPI(query) {
	try {
		const response = await fetch('https://vulners.com/api/v4/audit/host', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(query)
		});

		if (!response.ok) {
			throw new Error(`Vulners API request failed with status ${response.status}`);
		}

		const result = await response.json();
		return result;
	} catch (error) {
		console.error(`❌ Error querying Vulners API: ${error.message}`);
		throw error;
	}
}

function parseVulnerabilities(result) {
	const vulnerabilities = {
		low: [],
		medium: [],
		high: [],
		critical: []
	};

	if (result && result.result) {
		result.result.forEach((res) => {
			res.vulnerabilities.forEach((vulnerability) => {
				const severity = vulnerability.metrics.cvss.severity.toLowerCase();

				vulnerabilities[severity].push({
					title: vulnerability.title,
					description: vulnerability.short_description,
					ai_score: vulnerability.ai_score,
					cvss_score: vulnerability.metrics.cvss.score,
					cvss_severity: vulnerability.metrics.cvss.severity
				});
			});
		});
	}

	return vulnerabilities;
}

export {
	queryVulnersAPI,
	parseVulnerabilities
}