WebVax Project Setup and Execution Guide 🚀
1. Clone the Repository 🖥️
Start by cloning the repository to your local machine using Git. Open a terminal and run the following command:

bash
Copy
Edit
git clone https://github.com/vishnusaipriya7/Web_Vax.git
Next, navigate into the project directory:

bash
Copy
Edit
cd Web_Vax

---
2. Install Dependencies 📦
   
Once the project files are on your local machine, you'll need to install the required dependencies. Assuming the project uses Node.js, run the following command:

bash
Copy
Edit
npm install
This will install all necessary libraries and packages specified in the package.json file.


---
3. Set Up the Browser Extension 🌐
   
If WebVax includes a browser extension, follow these steps to set it up in your browser.

For Google Chrome:
Open Chrome and navigate to chrome://extensions/.

Enable Developer Mode by toggling the switch in the top-right corner.

Click on Load unpacked.

Select the folder where your extension code resides (this should contain the manifest.json file).

Your extension should now be active and ready for testing! ✅


---
4. Test the Extension and Application 🔍

Once the extension is loaded, open the browser and navigate to a website where WebVax is expected to detect vulnerabilities such as XSS, SQL Injection, and Open Redirects.

Here are examples of how to trigger these vulnerabilities:

XSS (Cross-Site Scripting) Vulnerability 💥
To test XSS, inject the following script into a form field, URL parameter, or any other input field that may not sanitize user input:

html
Copy
Edit
<script>alert('XSS')</script>
This will trigger an alert box on the page if the vulnerability is present and detected by the WebVax extension.


---

![image](https://github.com/user-attachments/assets/130f25a2-936f-4a92-a677-84cd302543a7)
![image](https://github.com/user-attachments/assets/d36ffdcf-8310-4fda-8350-f98580dfc4e4)
![image](https://github.com/user-attachments/assets/de78d9ed-3f7d-4c12-aab2-d64d1c03103b)
![image](https://github.com/user-attachments/assets/f3d935e4-8bb4-4ae5-90fa-579aa9ed6fc7)
![image](https://github.com/user-attachments/assets/39680f2f-3519-48c2-a212-cb4fec9bb36a)
![image](https://github.com/user-attachments/assets/aeb31073-4ce4-4048-9656-014c9b5d7cf0)
![image](https://github.com/user-attachments/assets/9e4536fc-4432-4632-a23a-40aeddd45aa5)
![image](https://github.com/user-attachments/assets/3f9291ff-bd0b-4e94-aa6b-b7fb193cf78e)








