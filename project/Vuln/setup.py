from setuptools import setup, find_packages

setup(
    name='webapp-security-scanner',
    version='1.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='A tool to scan web applications for various security vulnerabilities',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/webapp-security-scanner',  # Replace with your actual URL
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        'requests',
        'bs4',
        'nuclei',  # If you want to bundle nuclei as a dependency
    ],
    entry_points={
        'console_scripts': [
            'webapp-scanner=yourmodule:main',  # Replace 'yourmodule' with the module name of your script
        ],
    },
    python_requires='>=3.6',
    include_package_data=True,
)

