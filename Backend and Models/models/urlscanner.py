import numpy as np
from tensorflow.keras.models import load_model
import json

# Load model once globally
model = load_model('models/phishing_url_model.h5')

# Same tokenizer logic
char2idx = json.load(open('models/char2idx.json'))  # Save this from Colab too
max_len = 200

def url_to_seq(url):
    seq = [char2idx.get(c, 0) for c in url]
    if len(seq) < max_len:
        seq += [0] * (max_len - len(seq))
    else:
        seq = seq[:max_len]
    return np.array([seq])


