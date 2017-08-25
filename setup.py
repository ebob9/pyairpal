from setuptools import setup

setup(name='pyairpal',
      version='1.0.2',
      description='Python Client/SDK for Airpal',
      url='https://github.com/ebob9/pyairpal',
      author='Aaron Edwards',
      author_email='pyairpal@ebob9.com',
      license='MIT',
      install_requires=[
            'sseclient',
            'requests'
      ],
      packages=['pyairpal'])