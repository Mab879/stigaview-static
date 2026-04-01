from __future__ import annotations

import datetime
import logging
import pathlib
import re
import tomllib
from typing import Dict, List

from pydantic import BaseModel


def _stig_id_sort_key(stig_id: str) -> tuple:
    """Generate a sortable key from STIG ID for natural sorting.

    Extracts alphanumeric parts from STIG IDs and sorts them naturally:
    - RHEL-10-001020 sorts after RHEL-10-001000 (numeric comparison)
    - WN19-00-000010 sorts before WN19-AU-000100

    This allows numeric portions to be compared numerically rather than
    lexicographically.
    """
    parts = re.findall(r"[A-Za-z]+|\d+", stig_id)
    result = []
    for part in parts:
        if part.isdigit():
            result.append((0, int(part)))
        else:
            result.append((1, part))
    return tuple(result)


class Srg(BaseModel):
    srg_id: str
    title: str | None = None
    controls: list[Control] = []

    @property
    def url(self) -> str:
        return f"/srgs/{self.srg_id}"


class Control(BaseModel):
    srg: Srg
    vulnerability_id: str
    disa_stig_id: str
    severity: str
    title: str
    description: str
    fix: str
    check: str
    cci: List[str]
    stig: Stig

    def __repr__(self):
        return f"<Control {self.disa_stig_id}>"

    def __le__(self, other):
        return _stig_id_sort_key(self.disa_stig_id) <= _stig_id_sort_key(
            other.disa_stig_id
        )

    def __gt__(self, other):
        return _stig_id_sort_key(self.disa_stig_id) > _stig_id_sort_key(
            other.disa_stig_id
        )

    @property
    def url(self) -> str:
        return f"{self.stig.url}/{self.disa_stig_id}"

    @property
    def search_primary_key(self) -> str:
        return f"{self.stig.product.short_name}-{self.stig.short_version}-{self.disa_stig_id}"

    def to_search_json(self) -> Dict[str, str | List[str]]:
        return {
            "id": self.search_primary_key,
            "product": self.stig.product.short_name,
            "title": self.title,
            "description": self.description,
            "fix": self.fix,
            "check": self.check,
            "cci": self.cci,
            "stig": self.stig.short_version,
            "severity": self.severity,
            "path": self.url,
            "srg": self.srg.srg_id,
            "vulnerability_id": self.vulnerability_id,
            "release_date": self.stig.release_date.strftime("%Y-%m-%d"),
            "disa_stig_id": self.disa_stig_id,
        }


class Stig(BaseModel):
    release: int
    version: int
    release_date: datetime.date
    controls: List[Control] = []
    product: Product

    @property
    def short_version(self) -> str:
        return f"V{self.version}R{self.release}"

    @property
    def url(self) -> str:
        return f"{self.product.url}/{self.short_version.lower()}"

    def __repr__(self):
        return f"<Stig {self.short_version}>"

    def __le__(self, other):
        return self.release_date < other.release_date

    def __gt__(self, other):
        return self.release_date > other.release_date


class Product(BaseModel):
    full_name: str
    short_name: str
    stigs: list[Stig] = []

    @staticmethod
    def get_products(config: dict) -> list[Product]:
        products = list()
        products_path = pathlib.Path(config["products_path"])
        for product in products_path.iterdir():
            config_path = product.joinpath("product.toml")
            if not config_path.exists():
                logging.error(
                    f"Unable to find config for {product.name} at {str(config_path.absolute())}"
                )
                exit(5)
            with open(config_path, "r") as config_file:
                product_config = tomllib.loads(config_file.read())
                p = Product(
                    full_name=product_config["full_name"],
                    short_name=product_config["short_name"],
                )
                products.append(p)
        return products

    def sort_stigs(self):
        self.stigs = sorted(self.stigs)

    def __repr__(self):
        return repr((self.short_name, self.full_name))

    def __le__(self, other):
        return self.short_name < other.short_name

    def __gt__(self, other):
        return self.short_name > other.short_name

    @property
    def url(self) -> str:
        return f"/products/{self.short_name}"

    @property
    def latest_stig(self) -> Stig:
        self.sort_stigs()
        return self.stigs[-1]


class ProductConfig(BaseModel):
    full_name: str
    short_name: str
    stigs: Dict[str, Dict[str, datetime.date]]


class StigAViewConfig(BaseModel):
    title: str
    site_path: str
    products_path: str
    use_search: bool
