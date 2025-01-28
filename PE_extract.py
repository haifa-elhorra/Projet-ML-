"""
This is the main function of the PE classification of this program.
The library used to extract the features from the PE was pefile and you can find it here:
https://pypi.org/project/pefile/

In this program, we are first extracting the features from the PE and then providing it to the saved machine learning model. Using those features, we predict whether the PE is malicious or not.
"""

import pefile
import os
import array
import math
import pickle
import joblib
import sys
import argparse


# For calculating the entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


# For extracting the resources part
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


# For getting the version information
def get_version_info(pe):
    """Return version infos"""
    res = {}
    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            if hasattr(fileinfo, 'Key') and fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        res[entry[0]] = entry[1]
            if hasattr(fileinfo, 'Key') and fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    res[var.entry.items()[0][0]] = var.entry.items()[0][1]
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
            res['os'] = pe.VS_FIXEDFILEINFO.FileOS
            res['type'] = pe.VS_FIXEDFILEINFO.FileType
            res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
            res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
            res['signature'] = pe.VS_FIXEDFILEINFO.Signature
            res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


# extract the info for a given file using pefile
def get_version_info(pe):
    """Return version infos"""
    res = {}
    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            if hasattr(fileinfo, 'Key'):
                if fileinfo.Key == 'StringFileInfo':
                    for st in fileinfo.StringTable:
                        for entry in st.entries.items():
                            res[entry[0]] = entry[1]
                elif fileinfo.Key == 'VarFileInfo':
                    for var in fileinfo.Var:
                        res[var.entry.items()[0][0]] = var.entry.items()[0][1]

    # Ensure VS_FIXEDFILEINFO is properly accessed
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        vs_fixedfileinfo = pe.VS_FIXEDFILEINFO
        res['flags'] = vs_fixedfileinfo.FileFlags if hasattr(vs_fixedfileinfo, 'FileFlags') else 0
        res['os'] = vs_fixedfileinfo.FileOS if hasattr(vs_fixedfileinfo, 'FileOS') else 0
        res['type'] = vs_fixedfileinfo.FileType if hasattr(vs_fixedfileinfo, 'FileType') else 0
        res['file_version'] = vs_fixedfileinfo.FileVersionLS if hasattr(vs_fixedfileinfo, 'FileVersionLS') else 0
        res['product_version'] = vs_fixedfileinfo.ProductVersionLS if hasattr(vs_fixedfileinfo, 'ProductVersionLS') else 0
        res['signature'] = vs_fixedfileinfo.Signature if hasattr(vs_fixedfileinfo, 'Signature') else 0
        res['struct_version'] = vs_fixedfileinfo.StrucVersion if hasattr(vs_fixedfileinfo, 'StrucVersion') else 0

    return res



def extract_infos(file_path):
    """Extract features from the PE file"""
    data = {}

    # Load the PE file using pefile
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return data

    # Extract version information
    version_info = get_version_info(pe)
    for key, value in version_info.items():
        data[key] = value

    # Extract resource information
    resources = get_resources(pe)
    # For simplicity, we'll store the average entropy and size of resources
    if resources:
        avg_entropy = sum(resource[0] for resource in resources) / len(resources)
        avg_size = sum(resource[1] for resource in resources) / len(resources)
        data['avg_resource_entropy'] = avg_entropy
        data['avg_resource_size'] = avg_size
    else:
        data['avg_resource_entropy'] = 0
        data['avg_resource_size'] = 0

    # Add other feature extraction logic as needed (for example, section info, headers, etc.)

    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PE file classifier")
    parser.add_argument("file", help="Path to the PE file")
    args = parser.parse_args()

    # Loading the classifier.pkl and features.pkl
    clf = joblib.load('classifier.pkl')
    features = pickle.loads(open(os.path.join('features.pkl'), 'rb').read())

    # Extracting features from the PE file mentioned in the argument
    data = extract_infos(args.file)

    # Print extracted data and features for debugging
    print("Données extraites :", data)
    print("Caractéristiques attendues :", features)

    # Matching it with the features saved in features.pkl
    pe_features = [data.get(x, 0) for x in features]  # Use 0 as default if key is missing
    print("Features used for classification: ", pe_features)

    # Predicting if the PE is malicious or not based on the extracted features
    res = clf.prefit([pe_features])[0]
    print('The file %s is %s' % (os.path.basename(args.file), ['malicious', 'legitimate'][res]))
