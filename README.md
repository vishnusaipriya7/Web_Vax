WebVax Project Setup and Execution Guide
1. Clone the Repository
Start by cloning the repository to your local machine using Git. Open a terminal and run the following command:

bash
Copy
Edit
git clone https://github.com/vishnusaipriya7/Web_Vax.git
Navigate into the project directory:

bash
Copy
Edit
cd Web_Vax
2. Install Dependencies
Once you have the project files on your local machine, you need to install the required dependencies. Assuming the project uses Node.js, run the following command:

bash
Copy
Edit
npm install
This command will install all necessary libraries and packages specified in the package.json file.

3. Set Up the Browser Extension
If WebVax includes a browser extension, follow these steps to set it up in your browser.

For Google Chrome:

Open Chrome and navigate to chrome://extensions/.

Enable Developer Mode by toggling the switch in the top right corner.

Click on Load unpacked.

Select the folder where your extension code resides (this should contain the manifest.json file).

Your extension should now be active and available for testing.


4. Test the Extension and Application
Open the browser and navigate to a website where WebVax is expected to detect vulnerabilities (e.g., XSS, SQL Injection, etc.).

Verify that the extension is functioning as expected by checking for vulnerability notifications or any other feedback provided by the extension.

