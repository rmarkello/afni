"""
Functionality for parsing AFNI NIML files into JSON-validated Python
dictionaries.
"""

from collections import defaultdict
from collections.abc import ItemsView, KeysView, ValuesView
from pathlib import Path
import re
import subprocess as sp
import xml.etree.ElementTree as ET

# from jsonschema import validate

# this dictionary defines attributes in the NIML structure that need to be
# type converted prior to validation
# this should be used SPARINGLY, and is only meant for those values that AFNI
# chooses to write out as a "string" despite XML being capable of handling an
# alternative representation
_type_convert = {
    'ni_dimen': int
}

# this dictionary defines the mapping between the "ni_type" attribute in NIML
# and the Python datatype it should be mapped to; mostly self-explanatory
# except for the capitalized "String" NIML attribute
_type_mapping = {
    "int": int,
    "float": float,
    "String": str
}


def etree_to_json(t):
    """
    Converts XML-style ElementTree object to json-valid dictionary

    Parameters
    ----------
    t : xml.etree.ElementTree
        Tree to be converted. Attributes will be pre-pended with an "@" symbol
        and values with a "#" symbol to ensure reversibility of conversion

    Returns
    -------
    d : dict
        Converted XML-style ElementTree `t`

    References
    ----------
    http://www.xml.com/pub/a/2006/05/31/converting-between-xml-and-json.html
    https://stackoverflow.com/questions/2148119/how-to-convert-an-xml-string-to-a-dictionary
    """  # noqa

    d = {t.tag: {} if t.attrib else None}
    children = list(t)

    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_json, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}

    if t.attrib:
        d[t.tag].update({"@" + k: _type_convert.get(k, str)(v)
                         for k, v in t.attrib.items()})

    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
                d[t.tag]["#text"] = text
        else:
            d[t.tag] = text

    return d


def convert_niml_to_json(niml):
    """
    Converts `niml` string to JSON-valid dictionary

    Parameters
    ----------
    niml : str
        NIML-valid string

    Returns
    -------
    data : dict
        JSON-valid dictionary
    """

    return etree_to_json(ET.fromstring(niml))


def parse_dset_niml_json(niml_json, remove_attr_tag=False):
    """
    Parses JSON-converted NIML object into a more usable dictionary

    Parameters
    ----------
    niml_json : dict
        JSON-valid dictionary that has been converetd from an AFNI NIML string
    remove_attr_tag : bool, optional
        Whether to remove "@"/"#'-style attribute tags from `niml_json` keys;
        these may have been prepended during processing with `etree_to_json()`.
        Note that removing these may prevent reversibility of conversion.
        Default: False

    Returns
    -------
    data : dict
        JSON-valid dictionary that has converted entries in `niml_json` into
        more usable objects / datatypes
    """

    # if we're provided a list of dicts just call this on each of the values
    if type(niml_json) == list:
        return [parse_dset_niml_json(x, remove_attr_tag) for x in niml_json]

    # TODO: we assume that "AFNI_atr" is a list of attributes here -- is there
    #       a possibility that this might not be true??
    output = {}
    if "AFNI_atr" in niml_json.keys():
        output["AFNI_atr"] = parse_afni_attributes(niml_json["AFNI_atr"])

    for key in niml_json.keys():
        if key in output:
            continue
        elif key.startswith("@"):
            if remove_attr_tag:
                output[key.strip("@")] = niml_json[key]
            else:
                output[key] = niml_json[key]
        elif key.startswith("#"):
            value = niml_json[key]
            assert not value.startswith("<")
            output[key] = value
        else:
            value = parse_dset_niml_json(niml_json[key], remove_attr_tag)
            output[key] = value

    return output


def parse_afni_attributes(niml_json):
    """
    Parses entries of `niml_json` which have been extracted from AFNI NIML file

    Parameters
    ----------
    niml_json : list
        Assumes that each entry is a dictionary with at least keys ['@ni_type',
        '@ni_dimen', '@atr_name', '#text'].

    Returns
    -------
    parsed_attrs : dict
        Keys are extracted attribute names ('@atr_name') from each entry in
        list and values are taken from '#text'
    """

    parsed_attrs = {}
    for attribute in niml_json:
        # these are REQUIRED for well-formed attributes
        attr_type = _type_mapping[attribute.get("@ni_type")]
        attr_count = attribute.get("@ni_dimen")
        attr_name = attribute.get("@atr_name")

        # TODO: this may not be present for all attributes (e.g., ATLAS_POINTS)
        #       what's the best way forward?try
        parsed_attr = attribute.get("#text", '') \
                               .strip('\n "') \
                               .replace('"\n "', "")

        # if it's a string attribute, we _may_ have a few extra attributes;
        # let's check for those
        if attr_type is str:
            # check to see if the optional string attributes are present
            attr_delim = attribute.get("@atr_delim")
            attr_subtype = attribute.get("@atr_strtype")
            if attr_subtype == "niml-string":
                parsed_attr = parse_dset_niml_json(attribute)
            elif attr_subtype == "delim-string" and attr_delim is not None:
                parsed_attr = parsed_attr.split(attr_delim)
            elif attr_subtype == "byte-string":
                parsed_attr = bytes(parsed_attr)
        else:
            parsed_attr = [attr_type(f) for f in parsed_attr.split()]

        parsed_attrs[attr_name] = (
            parsed_attr[0] if len(parsed_attr) == 1 else parsed_attr
        )

    return parsed_attrs


def convert_afni_extension_niml(extension_niml, remove_attr_tag=False):
    """
    Converts AFNI NIML (NIfTI) extension to parsed JSON-vaild dictionary

    Parameters
    ----------
    extension_niml : str
        String taken from AFNI NIfTI extension
    remove_attr_tag : bool, optional
        Whether to remove "@"/"#'-style attribute tags from parsed NIML keys.
        There are generally prepended to keys during processing; note that
        removing these may prevent reversibility of conversion. Default: False

    Returns
    -------
    data : dict
    """

    # maybe we got a plain text NIML file
    try:
        niml = Path(extension_niml).read_text()
    # we might have gotten a file with a binary stream in it -- no good
    except UnicodeDecodeError as err:
        bytestr = Path(extension_niml).read_bytes()
        for search in [b'atr_strtype="byte-string"', b'ni_form="binary']:
            if re.search(search, bytestr):
                raise ValueError('Provided NIML file {} has embedded binary; '
                                 'stream not supported.'
                                 .format(extension_niml))
    # let's just assume we got a string, otherwise
    # FileNotFoundError: file doesn't exist
    # OSError: may have provided an XML string that's too long for a filename
    # TypeError: NoneType provide, etc
    except (FileNotFoundError, OSError, TypeError) as err:
        niml = extension_niml

    if niml is None:
        return None

    niml_dset_json = convert_niml_to_json(niml)

    # TODO: here is where validation should go
    # validate('schema.json', niml_dset_json)  # how to best "get" schema.json?

    dset_info = parse_dset_niml_json(niml_dset_json, remove_attr_tag)
    return dset_info


def make_afni_niml(data, preamble=None, root=None):
    """
    Creates AFNI NIML string from provided `data` dictionary

    Parameters
    ----------
    data : dict

    Returns
    -------
    niml : str
    """

    rev_type = {v: k for k, v in _type_mapping.items()}

    if preamble is None:
        preamble = "<?xml version='1.0' ?>\n"

    if root is None:
        root = ET.Element("AFNI_attributes")
    else:
        root = ET.SubElement(root, "AFNI_attributes")

    data = data.get('AFNI_attributes', {})

    for key, val in data.items():
        if key.startswith("@"):  # it's an attribute
            root.set(key.lstrip("@"), str(val))
        elif key == 'AFNI_atr':  # each entry should be a sub-element
            for k, v in val.items():
                tmproot = ET.SubElement(root, key)

                # try and understand the dtype / dimen
                # TODO: make this a little helper function?
                dtype, dimen = type(v), "1"
                if isinstance(v, list):
                    dtype = list(set(type(entry) for entry in v))[0]
                    dimen = str(len(v))

                    if dtype is str:
                        tmproot.set("atr_strtype", "delim-string")
                        tmproot.set("atr_delim", "~")
                        v = "~".join(v)
                    else:
                        v = "\n ".join([str(ent) for ent in v])

                if isinstance(v, dict):
                    dimen = str(len(v['AFNI_attributes']['AFNI_atr']))
                    # it's a niml-string!!!
                    tmproot.set("atr_strtype", "niml-string")
                    # we don't need to use the returned string here; providing
                    # `tmproot` as the `root` for this function call will
                    # make sure that elements/subelements are added in-place
                    make_afni_niml(v, preamble='', root=tmproot)
                else:
                    tmproot.text = str(v)

                # three required attributes
                tmproot.set("atr_name", k)
                tmproot.set("ni_type", rev_type.get(dtype, "String"))
                tmproot.set("ni_dimen", dimen)

        else:  # it's the value (note: I don't think this will ever trigger)
            root.text = val

    tree = ET.tostring(root, encoding="unicode", short_empty_elements=False)
    # the returned string doesn't have any nice new-line characters, etc
    # it would be _great_ if it did, though...
    for rep, tar in zip(['</', '><', '>', '">', '(\S+)="(\S+)"'],
                        ['\n</', '>\n<', '>\n ', '" >', '\n  \g<1>="\g<2>"']):
        tree = re.sub(rep, tar, tree)
    return preamble + tree


def read_atlas_niml(fname):
    """
    Reads in an AFNI atlas NIML file (somewhat non-standard structure)

    Parameters
    ----------
    fname : str
        Path to AFNI atlas NIML file

    Returns
    -------
    niml : str
        String containing NIML from an AFNI atlas NIML
    """

    niml_txt = Path(fname).read_text()
    niml_cleaned_txt = "\n".join(
        [x for x in niml_txt.splitlines() if not (x.startswith("#") or x == "")]
    )
    niml_cleaned_txt = niml_cleaned_txt.replace("&", "and")

    p = re.compile('(\\\\n"\n( *)")')
    niml_cleaned_txt = p.sub("(?2)", niml_cleaned_txt)
    niml_cleaned_txt = niml_cleaned_txt.replace('\\n"', '"')

    return "<doc> \n" + niml_cleaned_txt + "</doc>"


class AFNINIML(dict):
    """ Holder for parsed AFNI NIML information
    """

    def __init__(self, niml):
        self.niml = niml
        try:
            self.data = convert_afni_extension_niml(self.niml)
        except TypeError:
            self.data = self.niml
        super().__init__(**self.data)

        # I don't like this at all...
        for k, v in self.data['AFNI_attributes']['AFNI_atr'].items():
            if isinstance(v, dict) and 'AFNI_attributes' in v:
                self['AFNI_attributes']['AFNI_atr'][k] = self.__class__(v)

    def __getitem__(self, item):
        # this is ALSO a mess (#butitworks)
        try:
            return super().__getitem__(item)
        except KeyError:
            try:
                return super().__getitem__('AFNI_attributes') \
                              .__getitem__(item)
            except KeyError:
                try:
                    return super().__getitem__('AFNI_attributes') \
                                  .__getitem__('AFNI_atr') \
                                  .__getitem__(item)
                except KeyError:
                    raise KeyError(item)

    def get(self, item, default=None):
        try:
            return self.__getitem__(item)
        except KeyError:
            return default

    # TODO: override __repr__ to strip the 'AFNI_attributes' and 'AFNI_atr'
    #       out of the returned representation so users know to just provide
    #       the keys they want?

    # TODO: override keys(), values(), and items() so that they return what we
    #       would want (that is, not 'AFNI_attributes' and 'AFNI_atr')
