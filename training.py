import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
import joblib
from collections import Counter


# Feature Engineering Functions

class XSS_FeatureExtractor:
    def __init__(self):
        self.special_chars = ['<', '>', '"', "'", '=', '/', '\\', '(', ')', '{', '}', '[', ']', '&', ';', '%']
        


    def payload_length(self, payload):
        return len(payload)

    def number_of_special_chars(self, payload):
        return sum(payload.count(char) for char in self.special_chars)


    def contains_attr_src(self, payload):
        return int(bool(re.search(r'src\s*=\s*["\']', payload, re.IGNORECASE)))

    def contains_event_onload(self, payload):
        return int(bool(re.search(r'onload\s*=\s*["\']', payload, re.IGNORECASE)))


    def contains_event_onmouseover(self, payload):
        return int(bool(re.search(r'onmouseover\s*=\s*["\']', payload, re.IGNORECASE)))

    def contains_cookie(self, payload):
        return int(bool(re.search(r'document\.cookie|cookie\s*=', payload, re.IGNORECASE)))

    def contains_tag_script(self, payload):
        return int(bool(re.search(r'<script[^>]*>|<\\/script>', payload, re.IGNORECASE)))

    def contains_tag_iframe(self, payload):
        return int(bool(re.search(r'<iframe[^>]*>|<\\/iframe>', payload, re.IGNORECASE)))

    def contains_tag_meta(self, payload):
        return int(bool(re.search(r'<meta[^>]*(http-equiv|content)\s*=', payload, re.IGNORECASE)))
    
    def contains_tag_embed(self, payload):
        return int(bool(re.search(r'<embed\b', payload, re.IGNORECASE)))

    def contains_tag_link(self, payload):
        return int(bool(re.search(r'<link\b', payload, re.IGNORECASE)))

    def contains_tag_svg(self, payload):
        return int(bool(re.search(r'<svg\b', payload, re.IGNORECASE)))

    def contains_tag_frame(self, payload):
        return int(bool(re.search(r'<frame\b', payload, re.IGNORECASE)))

    def contains_tag_form(self, payload):
        return int(bool(re.search(r'<form\b', payload, re.IGNORECASE)))

    def contains_tag_div(self, payload):
        return int(bool(re.search(r'<div\b', payload, re.IGNORECASE)))

    def contains_tag_style(self, payload):
        return int(bool(re.search(r'<style\b', payload, re.IGNORECASE)))

    def contains_tag_img(self, payload):
        return int(bool(re.search(r'<img\b', payload, re.IGNORECASE)))

    def contains_tag_input(self, payload):
        return int(bool(re.search(r'<input\b', payload, re.IGNORECASE)))

    def contains_tag_textarea(self, payload):
        return int(bool(re.search(r'<textarea\b', payload, re.IGNORECASE)))

    def contains_attr_action(self, payload):
        return int(bool(re.search(r'action\s*=\s*["\']', payload, re.IGNORECASE)))

    def contains_attr_background(self, payload):
        return int(bool(re.search(r'background\s*=\s*["\']', payload, re.IGNORECASE)))

    def contains_attr_classid(self, payload):
        return int(bool(re.search(r'classid\s*=\s*["\']', payload, re.IGNORECASE)))
    def contains_attr_href(self, payload):
        return int(bool(re.search(r'href\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_attr_longdesc(self, payload):
        return int(bool(re.search(r'longdesc\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_attr_profile(self, payload):
        return int(bool(re.search(r'profile\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_attr_src(self, payload):
        return int(bool(re.search(r'src\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_attr_usemap(self, payload):
        return int(bool(re.search(r'usemap\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_attr_http_equiv(self, payload):
        return int(bool(re.search(r'http-equiv\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onblur(self, payload):
        return int(bool(re.search(r'onblur\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onchange(self, payload):
        return int(bool(re.search(r'onchange\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onclick(self, payload):
        return int(bool(re.search(r'onclick\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onerror(self, payload):
        return int(bool(re.search(r'onerror\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onfocus(self, payload):
        return int(bool(re.search(r'onfocus\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onkeydown(self, payload):
        return int(bool(re.search(r'onkeydown\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onkeypress(self, payload):
        return int(bool(re.search(r'onkeypress\s*=\s*["\']', payload, re.IGNORECASE)))

    def contains_event_onload(self, payload):
            return int(bool(re.search(r'onload\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onmousedown(self, payload):
        return int(bool(re.search(r'onmousedown\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onmouseout(self, payload):
        return int(bool(re.search(r'onmouseout\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onmouseover(self, payload):
        return int(bool(re.search(r'onmouseover\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onmouseup(self, payload):
        return int(bool(re.search(r'onmouseup\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def contains_event_onsubmit(self, payload):
        return int(bool(re.search(r'onsubmit\s*=\s*["\']', payload, re.IGNORECASE)))
    
    def number_of_evil_keywords(self, payload):
        evil_keywords = r'(eval|exec|script|javascript|vbscript|expression|data:|alert)'
        return len(re.findall(evil_keywords, payload, re.IGNORECASE))
    
    def js_file_included(self, payload):
        return int(bool(re.search(r'<script\b[^>]*src\s*=', payload, re.IGNORECASE)))
    
    def js_pseudo_protocol(self, payload):
        return int(bool(re.search(r'(javascript|vbscript|data):', payload, re.IGNORECASE)))
    
    def js_dom_location(self, payload):
        return int(bool(re.search(r'location\.(href|assign|replace)', payload, re.IGNORECASE)))
    
    def js_dom_document(self, payload):
        return int(bool(re.search(r'document\.(write|writeln|cookie)', payload, re.IGNORECASE)))
    
    def js_prop_cookie(self, payload):
        return int(bool(re.search(r'(document\.cookie|Set-Cookie)', payload, re.IGNORECASE)))
    
    def js_prop_referrer(self, payload):
        return int(bool(re.search(r'document\.referrer', payload, re.IGNORECASE)))

    def js_method_getElementsByTagName(self, payload):
        return int(bool(re.search(r'\.getElementsByTagName\s*\(', payload, re.IGNORECASE)))
    
    def js_method_getElementsById(self, payload):
        return int(bool(re.search(r'\.getElementById\s*\(', payload, re.IGNORECASE)))
    
    def js_method_alert(self, payload):
        return int(bool(re.search(r'(^|\s|;)alert\s*\(', payload, re.IGNORECASE)))
    
    def js_method_eval(self, payload):
        """F59: Detect eval method usage"""
        return int(bool(re.search(r'(^|\s|;)eval\s*\(', payload, re.IGNORECASE)))
    
    def js_method_fromCharCode(self, payload):
        return int(bool(re.search(r'\.fromCharCode\s*\(', payload, re.IGNORECASE)))
    
    def js_method_config(self, payload):
        return int(bool(re.search(r'\.config\s*\(', payload, re.IGNORECASE)))
    
    def js_min_length(self, payload):
        scripts = re.findall(r'<script[^>]*>([\s\S]*?)<\/script>', payload, re.IGNORECASE)
        return min(len(script) for script in scripts) if scripts else 0
    
    def js_min_define_function(self, payload):
        scripts = re.findall(r'<script[^>]*>([\s\S]*?)<\/script>', payload, re.IGNORECASE)
        return min(script.count('function') for script in scripts) if scripts else 0
    
    def js_min_function_calls(self, payload):
        scripts = re.findall(r'<script[^>]*>([\s\S]*?)<\/script>', payload, re.IGNORECASE)
        return min(len(re.findall(r'(\w+)\s*\(', script)) for script in scripts) if scripts else 0
    
    def js_string_max_length(self, payload):
        scripts = re.findall(r'<script[^>]*>([\s\S]*?)<\/script>', payload, re.IGNORECASE)
        max_len = 0
        for script in scripts:
            strings = re.findall(r'["\'](.*?)["\']', script)
            max_len = max(max_len, max(len(s) for s in strings) if strings else 0)
        return max_len
    
 

    def extract_all_features(self, row):

              features = {}      ;
              payload = row['payload'];
              features.update({'F0': self.payload_length(payload),
            'F1': self.number_of_special_chars(payload),
            'F2': self.contains_tag_script(payload),
            'F3': self.contains_tag_iframe(payload),
            'F4': self.contains_attr_src(payload),
            'F5': self.contains_event_onload(payload),
            'F6': self.contains_event_onmouseover(payload),
            'F7': self.contains_cookie(payload),
            'F8': self.contains_tag_script(payload),
            'F9': self.contains_tag_iframe(payload),
            'F10': self.contains_tag_meta(payload),
            'F11': self.contains_tag_embed(payload),
            'F12': self.contains_tag_link(payload),
            'F13': self.contains_tag_svg(payload),
            'F14': self.contains_tag_frame(payload),
            'F15': self.contains_tag_form(payload),
            'F16': self.contains_tag_div(payload),
            'F17': self.contains_tag_style(payload),
            'F18': self.contains_tag_img(payload),
            'F19': self.contains_tag_input(payload),
            'F20': self.contains_tag_textarea(payload),
            'F21': self.contains_attr_action(payload),
            'F22': self.contains_attr_background(payload),
            'F23': self.contains_attr_classid(payload),
            'F24': self.contains_attr_href(payload),
            'F25': self.contains_attr_longdesc(payload),
            'F26': self.contains_attr_profile(payload),
            'F27': self.contains_attr_src(payload),
            'F28': self.contains_attr_usemap(payload),
            'F29': self.contains_attr_http_equiv(payload),
            'F30': self.contains_event_onblur(payload),
            'F31': self.contains_event_onchange(payload),
            'F32': self.contains_event_onclick(payload),
            'F33': self.contains_event_onerror(payload),
            'F34': self.contains_event_onfocus(payload),
            'F35': self.contains_event_onkeydown(payload),
            'F36': self.contains_event_onkeypress(payload),
            'F37': self.contains_event_onload(payload),
            'F38': self.contains_event_onmousedown(payload),
            'F39': self.contains_event_onmouseout(payload),
            'F40': self.contains_event_onmouseover(payload),
            'F41': self.contains_event_onmouseup(payload),
            'F42': self.contains_event_onsubmit(payload),
            'F43': self.number_of_evil_keywords(payload),
            'F44': self.js_file_included(payload),
            'F45': self.js_pseudo_protocol(payload),
            'F46': self.js_dom_location(payload),
            'F47': self.js_dom_document(payload),
            'F48': self.js_prop_cookie(payload),
            'F49': self.js_prop_referrer(payload),
            'F50': self.js_method_getElementsByTagName(payload),
            'F51': self.js_method_getElementsById(payload),
            'F52': self.js_method_alert(payload),
            'F53': self.js_method_eval(payload),
            'F54': self.js_method_fromCharCode(payload),
            'F55': self.js_method_config(payload),
            'F56': self.js_min_length(payload),
            'F57': self.js_min_define_function(payload),
            'F58': self.js_min_function_calls(payload),
            'F59': self.js_string_max_length(payload)
        })
              return pd.Series(features)
              # 1. Load and shuffle data
df = pd.read_csv('Cleaned_XSS_dataset.csv')
df['payload'] = df['payload'].astype(str)
df = df.drop_duplicates(subset=['payload'], keep='first')  # <-- KEY ADDITION
print(f"Removed {len(df) - len(df.drop_duplicates())} duplicates")
df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle

# --- Feature Extraction ---
extractor = XSS_FeatureExtractor()
features_df = df.apply(extractor.extract_all_features, axis=1)
final_df = pd.concat([df, features_df], axis=1).fillna(0)

# After feature extraction and final_df creation...


# 1. Split into benign and malicious
benign = final_df[final_df['label'] == 0]
malicious = final_df[final_df['label'] == 1]

# 2. Create training set (70% of total data, 60% benign / 40% malicious)
train_size = int(0.7 * len(final_df))
benign_train_size = int(0.6 * train_size)
malicious_train_size = train_size - benign_train_size

benign_train = benign.sample(n=benign_train_size, random_state=42,replace=True)
malicious_train = malicious.sample(n=malicious_train_size, random_state=42,replace=True)
train_df = pd.concat([benign_train, malicious_train])

# 3. Create test set from remaining data (30% total, 75% benign / 25% malicious)
remaining_benign = benign.drop(benign_train.index)
remaining_malicious = malicious.drop(malicious_train.index)

test_size = int(0.3 * len(final_df))
benign_test_size = int(0.75 * test_size)
malicious_test_size = test_size - benign_test_size

# Take what's available if we don't have enough for exact ratios
benign_test = remaining_benign.sample(n=min(benign_test_size, len(remaining_benign)), random_state=42)
malicious_test = remaining_malicious.sample(n=min(malicious_test_size, len(remaining_malicious)), random_state=42)
test_df = pd.concat([benign_test, malicious_test])

# 4. Verify no leakage
common_indices = set(train_df.index) & set(test_df.index)
assert len(common_indices) == 0, f"Data leakage! {len(common_indices)} samples appear in both sets"

# 5. Prepare features and labels
X_train = train_df.drop(columns=['payload', 'label'])
y_train = train_df['label']
X_test = test_df.drop(columns=['payload', 'label'])
y_test = test_df['label']

# 6. Train/validation split (20% of training data)
X_train, X_val, y_train, y_val = train_test_split(
    X_train, y_train,
    test_size=0.2,
    random_state=42,
    stratify=y_train
)

# --- Train XGBoost with the article param:
model = XGBClassifier(
    n_estimators=400,
    max_depth=5,
    learning_rate=0.1,
    gamma=0,
    subsample=0.2,
    colsample_bytree=1.0,
    colsample_bylevel=1.0,
    objective='binary:logistic',
    eval_metric='logloss',
    early_stopping_rounds=40,

)

model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=True
)

# --- Evaluate ---
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
print("Accuracy:", accuracy_score(y_test, y_pred))
# --- Verify Distributions ---
print("\n=== Dataset Distribution ===")
print(f"Training set: {len(train_df)} payloads")
print(f"- Benign: {len(train_df[train_df['label'] == 0])} ({len(train_df[train_df['label'] == 0])/len(train_df)*100:.1f}%)")
print(f"- Malicious: {len(train_df[train_df['label'] == 1])} ({len(train_df[train_df['label'] == 1])/len(train_df)*100:.1f}%)")

print(f"\nTest set: {len(test_df)} payloads")
print(f"- Benign: {len(test_df[test_df['label'] == 0])} ({len(test_df[test_df['label'] == 0])/len(test_df)*100:.1f}%)")
print(f"- Malicious: {len(test_df[test_df['label'] == 1])} ({len(test_df[test_df['label'] == 1])/len(test_df)*100:.1f}%)")

# --- Save Model ---
joblib.dump(model, 'xgbxss_model.pkl')

