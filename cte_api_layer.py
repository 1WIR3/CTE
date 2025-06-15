#!/usr/bin/env python3
"""
🚀 CTE REST API - The Most Badass Threat Intelligence API Ever Built 🚀

Features:
- Lightning-fast async processing
- Real-time TTP correlation endpoints  
- Advanced filtering and search
- Bulk intelligence processing
- MISP integration endpoints
- Sigma rule generation
- Threat hunting query generation
- ML model serving for confidence scoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union
import asyncio
import json
import aiofiles
import logging
from datetime import datetime, timedelta
from custom_ttp_engine import SmartTTPEngine, TTPMapping
import hashlib
import io

# Configure epic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="🚀 CTE Intelligence API",
    description="Next-generation TTP correlation engine that makes traditional threat intel APIs look like toys",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine instance
engine = SmartTTPEngine()

# Pydantic Models for API
class IOCInput(BaseModel):
    ioc_value: str = Field(..., description="The IOC value to analyze")
    ioc_type: str = Field(..., description="Type of IOC (filename, sha256, command-line, etc.)")
    source: Optional[str] = Field(None, description="Source of the intelligence")
    
class BulkIOCInput(BaseModel):
    iocs: List[IOCInput] = Field(..., description="List of IOCs to process")
    min_confidence: Optional[float] = Field(70.0, description="Minimum confidence threshold")
    
class TTPMappingResponse(BaseModel):
    mitre_id: str
    technique_name: str
    ioc_type: str
    ioc_value: str
    confidence_score: float
    threat_actors: List[str]
    campaigns: List[str]
    kill_chain_phase: str
    detection_methods: List[str]
    false_positive_rate: float
    context: Dict
    
class AnalysisRequest(BaseModel):
    intelligence_data: List[Dict] = Field(..., description="Raw intelligence data")
    analysis_type: str = Field("comprehensive", description="Type of analysis to perform")
    confidence_threshold: float = Field(70.0, description="Confidence threshold for results")
    
class DetectionRuleRequest(BaseModel):
    mitre_techniques: List[str] = Field(..., description="MITRE techniques to generate rules for")
    rule_format: str = Field("sigma", description="Detection rule format (sigma, splunk, elastic)")
    severity: str = Field("medium", description="Rule severity level")
    
class ThreatHuntingRequest(BaseModel):
    threat_actor: Optional[str] = Field(None, description="Specific threat actor to hunt for")
    mitre_technique: Optional[str] = Field(None, description="Specific MITRE technique")
    time_range: str = Field("24h", description="Time range for hunting queries")
    platform: str = Field("splunk", description="SIEM platform for queries")

# Health Check Endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Check if the CTE engine is running and healthy"""
    stats = engine.get_intelligence_stats()
    return {
        "status": "🚀 CTE Engine is CRUSHING IT!",
        "engine_version": "2.0.0",
        "total_mappings": stats.get("total_mappings", 0),
        "uptime": "Available 24/7 because we're badass",
        "last_updated": datetime.now().isoformat()
    }

# Core Intelligence Analysis Endpoints
@app.post("/analyze/ioc", response_model=List[TTPMappingResponse], tags=["Intelligence Analysis"])
async def analyze_single_ioc(ioc: IOCInput):
    """Analyze a single IOC with our badass engine"""
    try:
        logger.info(f"🔍 Analyzing IOC: {ioc.ioc_type} | {ioc.ioc_value}")
        
        mappings = await engine.smart_ioc_analysis(ioc.ioc_value, ioc.ioc_type)
        
        if not mappings:
            raise HTTPException(status_code=404, detail="No high-confidence TTP mappings found")
            
        # Convert to response format
        response_mappings = []
        for mapping in mappings:
            response_mappings.append(TTPMappingResponse(
                mitre_id=mapping.mitre_id,
                technique_name=mapping.technique_name,
                ioc_type=mapping.ioc_type,
                ioc_value=mapping.ioc_value,
                confidence_score=mapping.confidence_score,
                threat_actors=mapping.threat_actors,