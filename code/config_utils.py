import yaml
import os
from pathlib import Path


DEFAULT_CONFIG = {
    'thresholds': {
        'epss': 0.36
    },
    'weights': {
        'cisa_kev': 1.0,
        'vulncheck_kev': 1.0,
        'epss': 0.9,
        'metasploit': 0.8,
        'nuclei': 0.6,
        'exploitdb': 0.4,
        'poc_github': 0.3
    },
    'scoring': {
        'high_threshold': 0.8,
        'functional_threshold': 0.6,
        'poc_threshold': 0.3
    },
    'enabled_sources': {
        'cisa_kev': True,
        'vulncheck_kev': True,
        'epss': True,
        'metasploit': True,
        'nuclei': True,
        'exploitdb': True,
        'poc_github': True
    }
}


def load_config(config_path='config.yaml'):
    """
    Load configuration from YAML file, or use defaults if file doesn't exist
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        dict: Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                user_config = yaml.safe_load(file)
                
            # Merge user config with defaults
            if user_config:
                # Update thresholds
                if 'thresholds' in user_config:
                    config['thresholds'].update(user_config['thresholds'])
                
                # Update weights
                if 'weights' in user_config:
                    config['weights'].update(user_config['weights'])
                
                # Update scoring thresholds
                if 'scoring' in user_config:
                    config['scoring'].update(user_config['scoring'])
                
                # Update enabled sources
                if 'enabled_sources' in user_config:
                    config['enabled_sources'].update(user_config['enabled_sources'])
            
            # Validate configuration
            validate_config(config)
            
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration instead.")
    else:
        print(f"Configuration file {config_path} not found. Using default configuration.")
    
    return config


def validate_config(config):
    """
    Validate configuration parameters
    
    Args:
        config (dict): Configuration dictionary
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Validate thresholds
    if 'epss' in config['thresholds']:
        epss_threshold = config['thresholds']['epss']
        if not 0 <= epss_threshold <= 1:
            raise ValueError(f"EPSS threshold must be between 0 and 1, got {epss_threshold}")
    
    # Validate weights
    for source, weight in config['weights'].items():
        if not 0 <= weight <= 1:
            raise ValueError(f"Weight for {source} must be between 0 and 1, got {weight}")
    
    # Validate scoring thresholds
    high_threshold = config['scoring']['high_threshold']
    functional_threshold = config['scoring']['functional_threshold']
    poc_threshold = config['scoring']['poc_threshold']
    
    if not 0 <= poc_threshold <= functional_threshold <= high_threshold <= 1:
        raise ValueError(
            f"Scoring thresholds must be in ascending order and between 0 and 1: "
            f"poc ({poc_threshold}) <= functional ({functional_threshold}) <= high ({high_threshold})"
        )


def calculate_weighted_score(row, config):
    """
    Calculate weighted score for a vulnerability based on its threat intelligence sources
    
    Args:
        row (pandas.Series): Row from vulnerability dataframe
        config (dict): Configuration dictionary
        
    Returns:
        float: Weighted score between 0 and 1
    """
    weights = config['weights']
    enabled_sources = config['enabled_sources']
    score = 0.0
    max_possible_score = 0.0
    
    # Consider only enabled sources
    for source, weight in weights.items():
        if enabled_sources.get(source, True):
            max_possible_score += weight
            
            # Special case for EPSS which is a continuous value
            if source == 'epss' and row['epss']:
                if isinstance(row['epss'], (int, float)) and row['epss'] >= config['thresholds']['epss']:
                    score += weight
            # Boolean intelligence sources
            elif row.get(source, False):
                score += weight
    
    # Normalize score to 0-1 range based on maximum possible score
    if max_possible_score > 0:
        return score / max_possible_score
    return 0.0