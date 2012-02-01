from distutils.core import setup

setup(name="globusonline-transfer-api-client",
      version="0.10.9",
      description="Globus Online Transfer API client library",
      author="Bryce Allen",
      author_email="ballen@ci.uchicago.edu",
      url="https://github.com/globusonline/transfer-api-client-python",
      packages=["globusonline", "globusonline.transfer",
                "globusonline.transfer.api_client"],
      keywords=["globusonline"],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "License :: OSI Approved :: Apache Software License",
          "Operating System :: MacOS :: MacOS X",
          "Operating System :: Microsoft :: Windows",
          "Operating System :: POSIX",
          "Programming Language :: Python",
          "Topic :: Communications :: File Sharing",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Software Development :: Libraries :: Python Modules",
          ],
      )
