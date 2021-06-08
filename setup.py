from setuptools import setup


setup(
    name = 'scan.py',
    python_requires='>3.6',
    version = '1.0',
    author = 'PTF569',
    packages = ['scan'],
    entry_points = {
        'console_scripts': [
            'scan.py = scan:__main__'
        ]
    })