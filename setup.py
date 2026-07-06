import os.path
from setuptools import setup, find_packages
from androidforensic import __version__, __website__, __package_name__

req = os.path.join(os.path.dirname(__file__), "requirements.txt")
with open(req, "rt", encoding="utf-8") as f:
    install_requires = [dep for dep in f.read().splitlines() if not dep.startswith("#")]

reme = os.path.join(os.path.dirname(__file__), "README.md")
with open(reme, "rt", encoding="utf-8") as f:
    long_description = f.read()


setup(
    name=__package_name__,
    scripts=[
        "androidforensic-gui.py",
        "androidforensic-cli.py",
        "androidforensic-tui.py",
        "andriller-gui.py",
    ],
    entry_points={
        "console_scripts": [
            "androidforensic=androidforensic.cli.main:cli",
            "androidforensic-gui=androidforensic:gui_main",
            "androidforensic-tui=androidforensic:tui_main",
        ]
    },
    version=__version__,
    description="AndroidForensic Everywhere | Multi-interface Android Forensic Toolkit",
    author="Denis Sazonov & Contributors",
    author_email="den@saz.lt",
    url=__website__,
    packages=find_packages(exclude=["tests*"]),
    license="MIT License",
    keywords="androidforensic andriller android forensic forensics adb dfir tui cli web".split(),
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=install_requires,
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.10",
    zip_safe=False,
)
