from setuptools import setup, find_packages

setup(
    name="nsctl",
    version="0.1.0",
    py_modules=find_packages(),
    entry_points={
        'console_scripts': [
            'nsctl = nsctl.cmds:main',
        ],
    }
)
