'''
Ripbin db... A new updgrade to support
- Much faster searching of bins in db 
    - SQL db to improve bin look up 
    - With the number of factors that can affect a binary, it was no longer 
        a good idea to use long paths to seperate bins based on factors 
- Handling for more language 
- Handling of files compiled different with same hashes
- Recoding of more information for each binary

Removing capabilites...
- Saving of labeled examples 
    - Labeling each bytes in 50GBs of binaries was calculated to 
        take roughly 15TeraBytes of storage if they were saved... no good 
- DB is no longer "deterministic" is the sense that the SQL file 
    needs to be synced with the current database.
    - Each binary will be saved to DB, then added to the DB 
    - Removing a binary will first remove from SQL then remove from DB
'''

import hashlib
from enum import Enum
from dataclasses import dataclass
import numpy as np
from pathlib import Path
import shutil
from typing import Union, Generator
import inspect
import pandas as pd
import json
import SQLAlchemy

from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base


# Information that is saved with a binary...
    # Compilationation...
        # Compiler 
            # Version
            # Toolchain 
        # Flags and arguments
        # Archetitecture
            # Target triplet
            # -or- tuple of OS / ARCH 
            # -or- etc
    # Post Comp Changes...
        # Binary rewriting strategy




