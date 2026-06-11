from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="aist",
    version="0.1.0",
    author="chiivy",
    description="Agentic Injection Security Tester",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chiivy/aist",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "httpx>=0.27.0",
        "structlog>=24.0.0",
        "click>=8.1.0",
        "jinja2>=3.1.0",
        "pyyaml>=6.0.0",
        "python-dotenv>=1.0.0",
        "rich>=13.0.0",
        "pyfiglet>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "aist=aist.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "security",
        "prompt injection",
        "ai security",
        "llm security",
        "agentic ai",
        "red teaming",
        "penetration testing",
    ],
)