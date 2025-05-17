import os
import subprocess

def run_command(command, cwd=None):
    result = subprocess.run(command, shell=True, cwd=cwd, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        exit(1)
    else:
        print(result.stdout)

def main():
    print("=== GitHub Auto-Push Script ===")
    
    folder_path = input("Enter the full path to your project folder: ").strip()
    commit_msg = input("Enter a commit message: ").strip()
    
    if not os.path.isdir(folder_path):
        print("Invalid folder path. Exiting.")
        return

    os.chdir(folder_path)

    if not os.path.exists(os.path.join(folder_path, ".git")):
        print("No Git repo found. Initializing...")
        run_command("git init")
        run_command("git remote add origin https://github.com/duharts/Configmgmtui.git")

    print("Adding files...")
    run_command("git add .")

    print("Committing changes...")
    run_command(f'git commit -m "{commit_msg}"')

    print("Pushing to GitHub...")
    run_command("git branch -M main")  # Ensure 'main' is the branch
    run_command("git push -u origin main")

    print("✅ Code pushed successfully to https://github.com/duharts/Configmgmtui")

if __name__ == "__main__":
    main()
