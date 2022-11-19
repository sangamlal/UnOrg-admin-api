def filter_dict_keys(dictionary, keys):
    result = {}
    for key in keys:
        if key in dictionary:
            result[key] = dictionary[key]

    return result
def get_model_fields(model: object):
    """
    :param model: Model Object
    :return: Model fields including child elements of referenced fields
    """
    meta_fields = model._meta.get_fields()
    output_fields = [f.name for f in meta_fields]

    return output_fields