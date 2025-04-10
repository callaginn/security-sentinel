import readline from 'readline';
import chalk from 'chalk';

async function getUserInput() {
	let hostname = process.argv[2];
	if (!hostname) {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout
		});
		
		hostname = await new Promise((resolve) => {
			rl.question(chalk.bold.cyan('\nPlease enter a hostname: '), (answer) => {
				rl.close();
				resolve(answer);
			});
		});
		
		if (!hostname) {
			console.error(chalk.red('No hostname provided. Exiting.'));
			process.exit(1);
		}
	}
	
	const url = `http://${hostname}`;
	return { hostname, url };
}

function wrapText(text, width = 80, linePrefix = '') {
	const lines = [];
	let currentText = text;
	
	if (!currentText) return ''; // Handle empty input
	
	// Process the text chunk by chunk
	while (currentText.length > 0) {
		// Check if the remaining text (with the line prefix) fits within the specified width.
		// If it fits, add it to the lines array and exit the loop.
		if ((linePrefix + currentText).length <= width) {
			lines.push(linePrefix + currentText);
			break;
		}
		
		// Calculate the maximum available width for the current line (excluding the line prefix).
		const availableWidth = width - linePrefix.length;
		let wrapPointInCurrent = -1;
		
		// Try to find the last space within the available width to wrap the line cleanly.
		if (availableWidth > 0) {
			wrapPointInCurrent = currentText.lastIndexOf(' ', availableWidth);
		}
		
		// If no suitable space is found within the available width, perform a hard wrap.
		if (wrapPointInCurrent <= 0) {
			// Hard wrap at the available width if it's greater than 0.
			wrapPointInCurrent = availableWidth > 0 ? availableWidth : 0;
			
			// Handle edge cases where the available width is 0 or less (e.g., when the prefix is too long).
			// This shouldn't normally happen with reasonable width and prefix values, but it's good to handle.
			if (wrapPointInCurrent <= 0) {
				// If no space is available, take at least one character from the current text.
				wrapPointInCurrent = 1;
			}
		}
		
		// Extract the line segment to add to the lines array, including the line prefix.
		const lineSegment = currentText.substring(0, wrapPointInCurrent);
		lines.push(linePrefix + lineSegment);
		
		// Update the remaining text by removing the processed segment and trimming leading spaces.
		currentText = currentText.substring(wrapPointInCurrent).trimStart();
	}
	
	return lines.join('\n');
}

export {
	getUserInput,
	wrapText
}