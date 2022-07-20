from setuptools import setup, find_packages

setup(
    name="dissect.hypervisor",
    packages=list(map(lambda v: "dissect." + v, find_packages("dissect"))),
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
    extras_require={
        "full": [
            "pycryptodome",
            "rich",
        ]
    },
    entry_points={
        "console_scripts": [
            "vma-extract=dissect.hypervisor.tools.vma:main",
            "envelope-decrypt=dissect.hypervisor.tools.envelope:main",
        ]
    },
)
