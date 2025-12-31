![Networking](https://i.imgur.com/Do3392o.jpeg)

-----------------

// todo: add badge status

# Network Course

This repo belongs to [Game Guild Networking Course](https://gameguild.gg/p/networking/). If you use this repo, consider yourself under the [Academic Honesty](https://gameguild.gg/academic-honesty). Read both throughly. If you have any questions, bug fix, or improvement proposal, raise an issue. Especially if you have found someone misusing the repo, we will file a DMCA takedown. Read the [LICENSE](./LICENSE.md) if you are in doubt.

**WARNING: IF YOU ARE A STUDENT IN THE CLASS, DO NOT DIRECTLY FORK THIS REPO. DO NOT PUSH PROJECT SOLUTIONS PUBLICLY. THIS IS AN ACADEMIC INTEGRITY VIOLATION AND CAN LEAD TO GETTING YOUR DEGREE REVOKED, EVEN AFTER YOU GRADUATE.**

**WARNING: IF YOU ARE A STUDENT OUTSIDE CHAMPLAIN, DO NOT MAKE YOUR SOLUTION PUBLICLY AVAILABLE, AND DO SUBMIT YOUR OWN WORK. OTHERWISE, YOU WILL BE BANNED FROM GAMEGUILD AND REPORTED ON GITHUB** Thank you for creating a fair learning environment.

## Cloning this Repository

The following instructions are adapted from the GitHub documentation on [duplicating a repository](https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/creating-a-repository-on-github/duplicating-a-repository). The procedure below walks you through creating a private network repository that you can use for development.

Alternativelly, you may want to follow this process on any **GOOD** GIT-GUI tools. Such as [git-fork](https://git-fork.com/), [SmartGit](https://www.smartgit.dev/download/), or [GitKraken](https://www.gitkraken.com/).

1. [Create a new repository](https://github.com/new) under your account. Pick a name (e.g. `network-private`) and select **Private** for the repository visibility level.
2. On your development machine, create a bare clone of the public network repository:
   ```console
   $ git clone --bare https://github.com/gameguild-gg/network.git network-public
   ```
3. Next, [mirror](https://git-scm.com/docs/git-push#Documentation/git-push.txt---mirror) the public network repository to your own private network repository. Suppose your GitHub name is `student` and your repository name is `network-private`. The procedure for mirroring the repository is then:
   ```console
   $ cd network-public
   
   # If you pull / push over HTTPS
   $ git push https://github.com/student/network-private.git master

   # If you pull / push over SSH
   $ git push git@github.com:student/network-private.git master
   ```
   This copies everything in the public network repository to your own private repository. You can now delete your local clone of the public repository:
   ```console
   $ cd ..
   $ rm -rf network-public
   ```
4. Clone your private repository to your development machine:
   ```console
   # If you pull / push over HTTPS
   $ git clone https://github.com/student/network-private.git

   # If you pull / push over SSH
   $ git clone git@github.com:student/network-private.git
   ```
5. Add the public network repository as a second remote. This allows you to retrieve changes from the gameguild-gg repository and merge them with your solution throughout the semester:
   ```console
   $ git remote add public https://github.com/gameguild-gg/network.git
   ```
   You can verify that the remote was added with the following command:
   ```console
   $ git remote -v
   origin	https://github.com/student/network-private.git (fetch)
   origin	https://github.com/student/network-private.git (push)
   public	https://github.com/gameguild-gg/network.git (fetch)
   public	https://github.com/gameguild-gg/network.git (push)
   ```
6. You can now pull in changes from the public network repository as needed with:
   ```console
   $ git pull public master
   ```
7. **Enable GitHub Actions** from the project settings of your private repository on github.com;
   ```
   Settings > Actions > General > Actions permissions > Allow All actions and reusable workflows
   Settings > Actions > General > Workflow permissions > Read and write permissions
   ```
8. Add your itstructor username as a collaborator to your private repository so they can view your code and help you debug issues.
  ```
  Settings > Collaborators and teams > Manage access > Add people
  ```

## Build

We recommend developing networking on Ubuntu 24.04, macOS (M1/M2/Intel) or Windows (strictly through `CLion`). We do not support any other environments (i.e., do not open issues or come to office hours to debug them). We do not support WSL. The grading environment runs
Ubuntu 24.04. 

### Windows or any OS with CLion

Open the CMakeLists.txt file in CLion, and it should automatically configure the project for you. If you have any issues, please refer to the [CLion documentation](https://www.jetbrains.com/help/clion/clion-quick-start-guide.html).

### Linux (Recommended) / macOS (Development Only)

Make sure you have the following dependencies installed:

- CMake 3.20 or higher;
- A C++17 compatible compiler (GCC 9 or higher, Clang 10 or higher, or MSVC 2019 or higher);
- Git;
- Ninja (optional, but recommended for faster builds).

Then run the following commands to build the system:

```console
$ mkdir build
$ cd build
$ cmake ..
$ make
```

If you want to compile the system in debug mode, pass in the following flag to cmake:
Debug mode:

```console
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make -j`nproc`
```
This enables [AddressSanitizer](https://github.com/google/sanitizers) by default.

If you want to use other sanitizers,

```console
$ cmake -DCMAKE_BUILD_TYPE=Debug -DBUSTUB_SANITIZER=thread ..
$ make -j`nproc`
```

There are some differences between macOS and Linux (i.e., mutex behavior) that might cause test cases
to produce different results in different platforms. We recommend students to use a Linux VM for running
test cases and reproducing errors whenever possible.

## IDE Setup

You may want to use any IDE of your choice, but I will be using JetBrains IDEs for this course, so it will be easier to follow along if you do the same. VS Code is also a good choice, but I will not be providing specific instructions for it, besides that, the contextual autocomplete and other features in JetBrains IDEs are generally better.

1. (Optional) [Apply for Jetbrains Student License](https://www.jetbrains.com/academy/student-pack/). A student license gives you free access to all JetBrains IDEs;
2. Install [Jetbrains Toolbox](https://www.jetbrains.com/toolbox-app/);
3. Login to Jetbrains Toolbox using your student account;
    - Once you log in, you will have access to all JetBrains IDEs for free as long as you are a student.
4. Install the following tools via Jetbrains Toolbox, they are free for students and non-commercial use
    - [CLion](https://www.jetbrains.com/clion/). This will be extensively used for assignments involving C/C++ programming.

::: warning "Disable AI Assistance"

Please disable AI assistance features (like GitHub Copilot, ChatGPT plugins, etc.) in any IDE you use for this course. Relying on AI tools can hinder your learning process and may lead to academic integrity issues. Read more about our [Academic Honesty](https://gameguild.gg/academic-honesty/).

On JetBrains IDEs, you can disable:

- AI assistance by going to `Settings/Preferences` > `Plugins` and disabling any AI-related plugins, such as
    - `GitHub Copilot`,
    - `Trae AI`,
    - or any other similar plugins you may have installed.
- In WebStorm, you can also disable AI code completion by going to `Settings/Preferences` > `Editor` > `General` > `Inline Completion` and unchecking the option for AI-based suggestions: such as
    - `Enable local Full Line completion Sugestions`,
    - `Enable automatic completion on typing`
    - `Enable multi-line suggestions`.

:::

## Repository structure

- Each assignment is in its own folder named `assignment-<number>`, e.g., `assignment-1`, `assignment-2`, etc.
- Each assignment folder contains:
    - `README.md`: Instructions for the assignment;
    - `docker-compose.yml`: Docker Compose file to set up the required environment;
    - Other files and folders as needed for the assignment, refer to the `README.md` in each assignment folder for details.
- `.github/workflows/`: Contains GitHub Actions workflows for automated testing of assignments. **Do not modify these files**.
- `.gitignore`: Specifies files and folders to be ignored by Git. You may modify this file if needed.
- `scripts/`: Contains helper scripts for running tests and other tasks. Do not modify these files.
- `reports/`: Will contain any generated files or outputs from assignments. Do not modify these files.

## Testing Assignments

- Each assignment includes automated tests that you can run locally using Docker.
- You may want to check the tab "Actions" on GitHub to see the results of automated tests run on your submissions.
- You may want to use `act` to run GitHub Actions workflows locally. Refer to [act documentation](https://github.com/nektos/act).