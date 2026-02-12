# Deployment Steps Using GitHub on macOS

This document outlines the steps to deploy your project using GitHub on a macOS system.

## Prerequisites
- macOS system
- Git installed (`brew install git`)
- GitHub account
- SSH key added to GitHub (recommended)
- Python and required dependencies installed (if applicable)

## 1. Clone the Repository
```
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

## 2. Set Up Python Environment (if needed)
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Make Changes and Commit
- Edit your files as needed.
- Stage and commit changes:
```
git add .
git commit -m "Describe your changes"
```

## 4. Push Changes to GitHub
```
git push origin main
```
*Replace `main` with your branch name if different.*

## 5. Deployment (General)
- If using GitHub Actions, ensure your workflow YAML is set up in `.github/workflows/`.
- For manual deployment, follow your project’s deployment instructions (e.g., upload files, run scripts).

## 6. Verify Deployment
- Check your deployed application or service.
- Review GitHub Actions logs if using CI/CD.

## 7. Troubleshooting
- Ensure SSH keys are configured: `ssh -T git@github.com`
- Check permissions and branch protection rules.
- Review error messages in terminal or GitHub Actions.

## 8. Start the Application Locally

After installing dependencies and configuring the app:

- For a single domain:
  ```
  python cli.py --domain example.com
  ```
- For bulk domains from a file:
  ```
  python cli.py --input domains.txt
  ```
- To generate reports:
  ```
  python cli.py report --output csv html
  ```

Run these commands in your project directory. Make sure your virtual environment is activated if you are using one.

## References
- [GitHub Docs: Connecting to GitHub with SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

---
*Update this document with project-specific deployment steps as needed.*
