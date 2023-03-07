# -*- coding: utf-8 -*-
from typing import Dict, List, Sequence, Union

from .cloudproof_findex import *

IndexedValuesAndKeywords = Dict[Union[Location, Keyword], Sequence[Union[str, Keyword]]]
SearchResults = Dict[Union[Keyword, str, bytes], List[Location]]
ProgressResults = Dict[Union[Keyword, str, bytes], List[Union[Location, Keyword]]]

__doc__ = cloudproof_findex.__doc__
if hasattr(cloudproof_findex, '__all__'):
    __all__ = cloudproof_findex.__all__
