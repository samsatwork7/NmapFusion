from setuptools import setup, find_packages

setup(
    name="nmapfusion",
    version="1.0.0",
    description="Enterprise Network Assessment Tool - Multi-File Nmap Fusion",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/nmapfusion",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "jinja2>=3.1.2",
        "openpyxl>=3.1.2",
        "defusedxml>=0.7.1",
        "python-dateutil>=2.8.2",
        "ipaddress>=1.0.23",
    ],
    entry_points={
        "console_scripts": [
            "nmapfusion=nmapfusion:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
)
