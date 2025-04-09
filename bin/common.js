import readline from 'readline';
import chalk from 'chalk';

async function getUserInput() {
	console.log();
	
	let hostname = process.argv[2];
	if (!hostname) {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout
		});
		
		hostname = await new Promise((resolve) => {
			rl.question(chalk.bold.cyan('Please enter a hostname: '), (answer) => {
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

function wrapText(text, width = 80, subsequentIndent = '') {
	const lines = [];
	let currentText = text;
	
	if (!currentText) return ''; // Handle empty input
	
	// Process the text chunk by chunk
	while (currentText.length > 0) {
		// Determine the effective width for this line.
		// The first line uses the full width. Subsequent lines need space for the indent.
		// However, we check length against the original width and add indent later if needed.
		const isFirstLine = lines.length === 0;
		const linePrefix = isFirstLine ? '' : subsequentIndent;
		
		// If the remaining text (with potential indent) fits, add it and break
		if ((linePrefix + currentText).length <= width) {
			lines.push(linePrefix + currentText);
			break;
		}
		
		// Calculate where to wrap this line (relative to the start of currentText)
		// We need to find the wrap point within the available space: width - linePrefix.length
		const availableWidth = width - linePrefix.length;
		let wrapPointInCurrent = -1;

		// Try finding the last space within the available width
		if (availableWidth > 0) {
			wrapPointInCurrent = currentText.lastIndexOf(' ', availableWidth);
		}
		
		// If no suitable space is found within availableWidth, we need to hard wrap.
		if (wrapPointInCurrent <= 0) {
			// Hard wrap at the available width.
			wrapPointInCurrent = availableWidth > 0 ? availableWidth : 0; // Avoid negative index if indent fills width
			
			// Edge case: If availableWidth is 0 or less (indent >= width),
			// push prefix and move on. This shouldn't happen with width=80/indent=4, but good to consider.
			if (wrapPointInCurrent <= 0 && !isFirstLine) {
				lines.push(linePrefix.substring(0, width)); // Push truncated indent? Or handle differently?
				// Decide how to handle text that can't even start after indent. Skip? Error?
				// For now, let's assume text processing continues, but this indicates an issue.
				// Let's just hard break the text itself at 1 char if wrapPointInCurrent is 0.
				if (wrapPointInCurrent === 0) wrapPointInCurrent = 1; // Take at least one char from currentText
			} else if (wrapPointInCurrent <= 0 && isFirstLine){
				// If even the first line needs hard wrap at 0 or less (width=0?), take 1 char.
				wrapPointInCurrent = 1;
			}
		}
		
		// Add the determined line segment (with prefix)
		const lineSegment = currentText.substring(0, wrapPointInCurrent);
		lines.push(linePrefix + lineSegment);
		
		// Update remaining text (trim space where we broke)
		currentText = currentText.substring(wrapPointInCurrent).trimStart();
	}
	
	return lines.join('\n');
}

export {
	getUserInput,
	wrapText
}