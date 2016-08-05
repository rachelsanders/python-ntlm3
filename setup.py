from setuptools import setup


setup(name='python-ntlm3',
      version='2.0.0-dev',
      description='Python 3 compatible NTLM library',
      long_description="""
      This package allows Python clients running on any operating
      system to provide NTLM authentication to a supporting server.
        """,
      author='Matthijs Mullender',
      author_email='info@zopyx.org',
      maintainer='Rachel Sanders',
      maintainer_email='rachel@trustrachel.com',
      url="https://github.com/trustrachel/python-ntlm3",
      packages=["ntlm3"],
      zip_safe=False,
      license="GNU Lesser GPL",
      # See https://pypi.python.org/pypi?%3Aaction=list_classifiers

      install_requires=[
          "six"
      ],

      classifiers=[
          "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
      ],
      )
