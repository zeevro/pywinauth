from setuptools import setup


setup(
    name='pywinauth',
    version='0.4.0',
    url='https://github.com/zeevro/pywinauth',
    download_url='https://github.com/zeevro/pywinauth/archive/master.zip',
    author='Zeev Rotshtein',
    author_email='zeevro@gmail.com',
    maintainer='Zeev Rotshtein',
    maintainer_email='zeevro@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: Public Domain',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Security',
        'Topic :: Utilities',
        'Typing :: Typed',
    ],
    license=None,
    description='A tool to generate TOTP code based using secrets from WinAuth',
    keywords=[
        'WinAuth',
        'TOTP',
        '2FA',
        'MFA',
    ],
    zip_safe=True,
    packages=[
        'winauth',
    ],
    install_requires=[
        'xmltodict',
        'pyotp',
        'pyperclip',
        'fuzzywuzzy',
        'qrcode',
    ],
    entry_points=dict(
        console_scripts=[
            'winauthc = winauth.__main__:main',
        ],
    ),
)
