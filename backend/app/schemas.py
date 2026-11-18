from typing import Literal

from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class EmailScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=1_000_000)


class ReviewRequest(BaseModel):
    decision: Literal["confirmed_phishing", "false_positive", "needs_more_evidence"]
    reason: str = Field(min_length=3, max_length=500)
