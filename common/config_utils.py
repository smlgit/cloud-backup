import pickle


def save_config(config_object, config_file_path, password):
    # Just using pickle

    with open(config_file_path, 'wb') as f:
        pickle.dump(config_object, f)


def get_config(config_file_path, password):

    with open(config_file_path, 'rb') as f:
        return pickle.load(f)
