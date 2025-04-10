import * as common from './bin/common.js';
import { getIpAddresses, testOpenSSHVersion } from './bin/network.js';

(async () => {
	const { hostname, url } = await common.getUserInput();
	const ipAddresses = await getIpAddresses(hostname);
	
	for (const ipAddress of ipAddresses) {
		await testOpenSSHVersion(ipAddress);
	}
})();
