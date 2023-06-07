from .nodeapi import NodeApi

def create(config):
    return NodeApi(config)
