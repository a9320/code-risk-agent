#!/usr/bin/env python3
"""Batch fix script for evaluation 5 issues."""
import os

# Fix 1: ChatML format in llm_client.py
print("[1/6] ChatML format...")
with open('core/llm_client.py', 'r') as f:
    c = f.read()
c = c.replace('_IM_START = "<im_start>"', '_IM_START = "<|im_start|>"')
c = c.replace('_IM_END = "<im_end>"', '_IM_END = "