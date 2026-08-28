import datetime
import logging
import multiprocessing
import os.path
import pathlib
import shutil
import xml.etree.ElementTree as ET
from typing import List

import minify_html
from jinja2 import Environment, FileSystemLoader
from tqdm import tqdm

from stigaview_static import models
from stigaview_static.json_output import render_json_control
from stigaview_static.utils import get_config, get_git_revision_short_hash


def _severity_to_cat(severity: str) -> str:
    """Convert severity level to DISA CAT level."""
    mapping = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
    return mapping.get(severity.lower(), severity)


def _cci_list_to_links(cci_list: list) -> str:
    """Convert a list of CCI IDs to HTML links."""
    return ", ".join(f'<a href="/ccis/{cci_id}">{cci_id}</a>' for cci_id in cci_list)


def _datetime_element(date_str: str) -> str:
    """Format date string to human-readable format."""
    return f'<time datetime="{date_str}">{date_str}</time>'


def render_template(template: str, out_path: str, **kwargs):
    file_loader = FileSystemLoader("templates")
    env = Environment(loader=file_loader)
    env.filters["severity_to_cat"] = _severity_to_cat
    env.filters["cci_list_to_links"] = _cci_list_to_links
    env.filters["datetime_element"] = _datetime_element
    template = env.get_template(template)
    config = get_config()
    context = kwargs | config
    output = template.render(git_sha=get_git_revision_short_hash(), **context)
    minified = minify_html.minify(output)
    with open(out_path, "w") as fp:
        fp.write(minified)


def render_product(product: models.Product, out_path: str):
    out_product = os.path.join(out_path, product.short_name)
    render_product_index(out_path, product)
    for stig in product.stigs:
        real_out_path = render_stig_detail(out_product, product, stig)
        for control in stig.controls:
            render_control(control, real_out_path)
            render_json_control(control, out_path)
    _copy_latest_stig(out_product, product)


def render_stig_detail(out_product, product, stig):
    real_out_path = os.path.join(out_product, stig.short_version.lower())
    real_out = os.path.join(real_out_path, "index.html")
    os.makedirs(real_out_path, exist_ok=True)
    render_template("stig.html", real_out, product=product, stig=stig)
    one_page_out = os.path.join(real_out_path, "onepage")
    stig.controls = sorted(stig.controls)
    render_onepage_stig_detail(one_page_out, product, stig)
    return real_out_path


def render_onepage_stig_detail(out_product, product, stig):
    real_out = os.path.join(out_product, "index.html")
    os.makedirs(out_product, exist_ok=True)
    render_template("one_page_stig.html", real_out, product=product, stig=stig)
    return out_product


def render_control(control, real_out_path):
    control_out_path = os.path.join(real_out_path, control.disa_stig_id)
    os.makedirs(control_out_path, exist_ok=True)
    control_out = os.path.join(control_out_path, "index.html")
    render_template("control.html", control_out, control=control)


def render_product_index(out_path, product):
    real_out = os.path.join(out_path, product.short_name)
    full_out_path = os.path.join(real_out, "index.html")
    os.makedirs(real_out, exist_ok=True)
    product.stigs = sorted(product.stigs)
    render_template("product.html", full_out_path, product=product)


def process_product_args(args):
    product, real_out = args
    return render_product(product, real_out)


def write_products(products: list[models.Product], out_path: str) -> None:
    logging.info("Beginning rendering products")
    real_out = os.path.join(out_path, "products")
    full_out_path = os.path.join(real_out, "index.html")
    os.makedirs(real_out, exist_ok=True)
    render_template("products.html", full_out_path, products=sorted(products))
    with multiprocessing.Pool(multiprocessing.cpu_count()) as pool:
        list(
            tqdm(
                pool.imap(
                    process_product_args, [(product, real_out) for product in products]
                ),
                total=len(products),
                desc="Rendering products",
                mininterval=0.5,
                unit="product",
            )
        )


def render_stig_index(products: list[models.Product], out_path: str) -> None:
    logging.info("Rendering stig index")
    real_out = os.path.join(out_path, "stigs")
    full_out_path = os.path.join(real_out, "index.html")
    os.makedirs(real_out, exist_ok=True)
    stigs = list()
    for product in products:
        for stig in product.stigs:
            stig.product = product
            stigs.append(stig)
    render_template("stigs.html", full_out_path, stigs=sorted(stigs))


def write_index(products: list[models.Product], out_path: str) -> None:
    logging.info("Writing index")
    stigs = list()
    for product in products:
        stigs.extend(product.stigs)

    def _sort_stigs_by_date(stig):
        return stig.release_date

    stigs = sorted(stigs, key=_sort_stigs_by_date)
    full_out_path = os.path.join(out_path, "index.html")
    render_template("index.html", full_out_path, stigs=sorted(stigs[-9:], reverse=True))


def render_srg_index(srgs: dict, out_path: str) -> None:
    logging.info("Rendering SRG index")
    real_out = os.path.join(out_path, "srgs")
    full_out_path = os.path.join(real_out, "index.html")
    os.makedirs(real_out, exist_ok=True)
    render_template("srgs.html", full_out_path, srgs=srgs)
    render_srg_details(srgs, out_path)


def render_srg_details(srgs: dict, out_path: str) -> None:
    for srg_id in tqdm(srgs.keys(), desc="Rendering SRG details", unit="page"):
        controls = srgs[srg_id]
        full_out_path = os.path.join(out_path, "srgs", srg_id)
        os.makedirs(full_out_path, exist_ok=True)
        full_out = os.path.join(full_out_path, "index.html")
        render_template("srg_detail.html", full_out, controls=controls, srg_id=srg_id)


def create_cci(project_root: str, out_path: str) -> None:
    logging.info("Processing CCI")
    real_out = os.path.join(out_path, "ccis")
    full_out_path = os.path.join(real_out, "index.html")
    os.makedirs(real_out, exist_ok=True)
    cci_path = (
        pathlib.Path(project_root).parent.joinpath("cci").joinpath("cci_list.xml")
    )
    ns = {"cci": "http://iase.disa.mil/cci"}
    cci_root = ET.parse(cci_path).getroot()
    disa_ccis: List[models.DisaCCI] = list()
    xml_ccis = cci_root.findall("cci:cci_items/cci:cci_item", ns)
    logging.debug("Processing CCI %s", len(xml_ccis))
    with tqdm(total=len(xml_ccis), desc="Processing CCI", unit="cci") as pbar:
        for cci in xml_ccis:
            id = cci.attrib["id"]
            status = cci.find("cci:status", ns).text
            publishdate = datetime.date.fromisoformat(
                cci.find("cci:publishdate", ns).text
            )
            contributor = cci.find("cci:contributor", ns).text
            definition = cci.find("cci:definition", ns).text
            type = cci.find("cci:type", ns).text
            references = []
            for reference in cci.findall("cci:references/cci:reference", ns):
                creator = reference.get("creator")
                title = reference.get("title")
                version = reference.get("version")
                location = reference.get("location")
                index = reference.get("index")
                if not all([creator, title, version, location]):
                    logging.warning(
                        "Skipping malformed reference for CCI %s: creator=%r title=%r version=%r location=%r index=%r",
                        id,
                        creator,
                        title,
                        version,
                        location,
                        index,
                    )
                    continue
                ref = models.DISACCIReference(
                    creator=creator,
                    title=title,
                    version=version,
                    location=location,
                    index=index,
                )
                references.append(ref)
                logging.debug("Processing reference for CCI %s: %s", id, ref)
            disa_cci = models.DisaCCI(
                id=id,
                status=status,
                publishdate=publishdate,
                contributor=contributor,
                definition=definition,
                type=type,
                references=references,
            )
            disa_ccis.append(disa_cci)
            cci_full_out_path = os.path.join(real_out, id.lower())
            os.makedirs(cci_full_out_path, exist_ok=True)
            cci_full_out = os.path.join(cci_full_out_path, "index.html")
            render_template(
                "cci.html", cci_full_out, disa_cci=disa_cci, disa_ccis=disa_ccis
            )
            pbar.update(1)

    render_template("ccis.html", full_out_path, disa_ccis=sorted(disa_ccis))


def _copy_latest_stig(out_product: str, product: models.Product):
    latest_stig = product.latest_stig
    current_versioned_root = os.path.join(
        out_product, latest_stig.short_version.lower()
    )
    product_latest_path = os.path.join(out_product, "latest")
    shutil.copytree(current_versioned_root, product_latest_path)
