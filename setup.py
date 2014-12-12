from setuptools import setup


setup(name='python-ntlm',
      version='2.0-dev',
      description='Python library that provides NTLM support, including an authentication handler for urllib2. '
                  'Works with pass-the-hash in additon to password authentication.',
      long_description="""
      This package allows Python clients running on any operating
      system to provide NTLM authentication to a supporting server.

      python-ntlm is probably most useful on platforms that are not
      Windows, since on Windows it is possible to take advantage of
      platform-specific NTLM support.

      This is also useful for passing hashes to servers requiring
      ntlm authentication in instances where using windows tools is
      not desirable.""",
      author='Matthijs Mullender',
      author_email='info@zopyx.org',
      maintainer='Daniel Holth',
      maintainer_email='dholth@gmail.com',
      url="http://code.google.com/p/python-ntlm",
      packages=["ntlm"],
      zip_safe=False,
      license="GNU Lesser GPL",
      # See https://pypi.python.org/pypi?%3Aaction=list_classifiers

      install_requires=[
          "six"
      ],

      classifiers=[
          "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)"
          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
      ],
      )
