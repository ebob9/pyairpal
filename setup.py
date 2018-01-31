from setuptools import setup

setup(name='pyairpal',
      version='1.1.2',
      description='Python Client/SDK for Airpal',
      url='https://github.com/ebob9/pyairpal',
      author='Aaron Edwards',
      author_email='pyairpal@ebob9.com',
      license='MIT',
      install_requires=[
            'requests>= 2.18.4',
            'sseclient >= 0.0.18'
      ],
      packages=['pyairpal'],
      classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
      ]
      )