# Contributing to Seigr

Thank you for your interest in contributing to Seigr! By supporting a modular, eco-driven, and resilient decentralized system, you’re helping pioneer a new paradigm for data management inspired by biomimetic principles and ethical computing. This guide outlines our contribution process, coding standards, areas for improvement, and steps for joining the Seigr community.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Setup](#development-setup)
3. [Cloning the Repository and Submodules](#cloning-the-repository-and-submodules)
4. [Contribution Guidelines](#contribution-guidelines)
5. [Areas of Focus](#areas-of-focus)
6. [Coding Standards](#coding-standards)
7. [Documentation Standards](#documentation-standards)
8. [Testing and Validation](#testing-and-validation)
9. [Continuous Integration and Workflow Checks](#continuous-integration-and-workflow-checks)
10. [Pull Request Process](#pull-request-process)
11. [Community](#community)
12. [License](#license)

---

## Getting Started

To contribute to Seigr, it’s beneficial to familiarize yourself with:
- **Decentralized Systems**: Knowledge of distributed networks, consensus protocols, and peer-to-peer architectures.
- **Cryptographic Standards**: Understanding hashing, encryption, and decentralized identity protocols will help when working on Seigr's secure layers.
- **Eco-Inspired Computing**: Seigr’s architecture follows nature-inspired principles, like self-healing and decentralized intelligence inspired by mycelium networks.

Whether you’re interested in developing new protocol buffers, optimizing data redundancy, or refining user interfaces, all contributions are welcome!

### Joining the Contributor Team

1. **Review the Issues Board**: Check [GitHub Issues](https://github.com/Seigr-lab/Seigr-EcoSystem/issues) for areas where contributions are most needed. 
2. **Join Discussions**: Participate in our community discussions, especially if you’re proposing significant changes. 
3. **Fork the Repository**: Start with a fork of the Seigr repo to work on changes independently.
4. **Introduce Yourself**: Feel free to introduce yourself in the `#contributions` channel on Discord and outline your areas of interest.

---

## Development Setup

### Prerequisites
- **Python** (3.8 or higher)
- **Protocol Buffers Compiler** (`protoc`)
- **Conda** for environment management

### Installation Steps

1. **Clone the Repository** (including submodules; see next section):
   ```bash
   git clone --recurse-submodules https://github.com/Seigr-lab/Seigr-EcoSystem.git
   cd Seigr-EcoSystem
   ```

2. **Set up the Development Environment**:
   ```bash
   conda env create -f environment.yml
   conda activate seigr
   ```

3. **Build Protocol Buffers**:
   - From the project root, build all protocol buffers:
     ```bash
     protoc --proto_path=seigr_protocol --python_out=src/ seigr_protocol/**/*.proto
     ```

4. **Run Tests**:
   - Ensure your environment is set up correctly by running the initial tests.
   ```bash
   python -m unittest discover -s src/tests
   ```

---

## Cloning the Repository and Submodules

Since **seigr-os** is a **submodule**, you must use the correct cloning method to avoid missing dependencies.

### **1️⃣ Cloning for the First Time (Recommended)**
```bash
git clone --recurse-submodules https://github.com/Seigr-lab/Seigr-EcoSystem.git
cd Seigr-EcoSystem
```
This ensures all submodules, including `seigr-os`, are cloned properly.

### **2️⃣ If You've Already Cloned the Repo**
If you previously cloned the repo **without** `--recurse-submodules`, run:
```bash
git submodule update --init --recursive
```
This initializes and fetches all submodules.

### **3️⃣ Keeping Submodules Updated**
To update the submodules after a pull:
```bash
git pull --recurse-submodules
git submodule update --recursive --remote
```
This ensures you always have the latest submodule changes.

---

## Contribution Guidelines

### Areas of Focus

Seigr benefits from contributions in various areas:
- **Protocol Buffers Development**: Expand Seigr’s modularity by contributing to protocol files in `seigr_protocol/`.
- **Eco-Friendly Encoding**: Explore senary encoding methods for energy-efficient storage and transmission.
- **AI-Driven Analytics**: Implement predictive maintenance, anomaly detection, and adaptive scaling.
- **Self-Healing Mechanisms**: Design and improve replication strategies for fault tolerance.
- **Community Documentation**: Help document the technical architecture and eco-inspired computing principles.
- **Security & Identity**: Work on secure identity management, access control, and cryptographic protocols.

### **Committing Changes to the Submodule**
Since `seigr-os` is a submodule, changes inside it must be committed separately.

#### **1️⃣ Making Changes in `seigr-os`**
```bash
cd seigr-os
git checkout development  # Ensure you're on the correct branch
git pull origin development  # Get latest changes
# Make your edits
git commit -am "Your commit message"
git push origin development
```

#### **2️⃣ Updating the Submodule Reference in the Main Repo**
After committing to `seigr-os`, return to the main repository:
```bash
cd ..
git add seigr-os
git commit -m "Updated seigr-os submodule reference"
git push origin development
```
This updates the reference to the latest commit in `seigr-os`.

---

## Pull Request Process

1. **Branch Naming**: Use descriptive branch names, e.g., `feature/smart-contract-protocol` or `fix/resource-management`.
2. **Commit Messages**: Use clear and concise commit messages. Example:
   ```plaintext
   feat(protocol): Add adaptive scaling configuration to resource_management.proto
   ```
3. **Pull Request Title**: Briefly describe your PR, e.g., “Add AI-Driven Analysis and Prediction Protocol.”
4. **Description**: Include details, such as the purpose of the change, which issues it addresses, and specific design choices.
5. **Link to Issues**: If your PR resolves an open issue, include `Closes #issue_number` in the PR description.

### **Pull Request Checklist**
When submitting a PR, ensure you have:
- [ ] Followed coding guidelines
- [ ] Updated submodules (if applicable)
- [ ] Passed all CI/CD checks
- [ ] Provided detailed descriptions and testing evidence

---

## Community

Our community is the foundation of Seigr. Here’s how you can participate:

- **Join our Discord**: The Seigr Discord server has dedicated channels for protocol discussions, eco-computing, and project updates.
- **Weekly Meetings**: Attend weekly developer meetings (schedule available on Discord).
- **Open Discussions**: Share ideas, feedback, or concerns in our GitHub Discussions.

---

## License

Seigr is dual-licensed under the **MIT License** and the **Provisional Rebel Earthling License (RE License) v0.1**, offering contributors the choice of a permissive license or an ethical alternative prioritizing transparency and community governance.

By contributing to Seigr, you agree to have your contributions licensed under both the MIT License and the RE License.

For more information on our licensing principles, please review the [LICENSE](LICENSE) and [RE_LICENSE](RE_LICENSE) files.

---

### **Final Notes**
🚀 Thank you for contributing to Seigr! Your work supports a resilient, adaptive, and eco-conscious ecosystem. If you have any questions, feel free to reach out to the community on Discord or GitHub. 🌱
