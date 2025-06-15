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
- Streaming responses for large datasets
- Advanced caching and rate limiting
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Union, Any
import asyncio
import json
import aiofiles
import logging
from datetime import datetime, timedelta
from custom_ttp_engine import SmartTTPEngine, TTPMapping
import hashlib
import io
import uuid
import time
from collections import defaultdict
import csv
from contextlib import asynccontextmanager

# Configure epic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Global variables
engine = None
request_cache = {}
rate_limiter = defaultdict(list)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    global engine
    logger.info("🚀 Initializing CTE Engine...")
    engine = SmartTTPEngine()
    await engine.initialize()
    logger.info("✅ CTE Engine initialized and ready to rock!")
    yield
    logger.info("👋 Shutting down CTE Engine...")

app = FastAPI(
    title="🚀 CTE Intelligence API",
    description="Next-generation TTP correlation engine that makes traditional threat intel APIs look like toys",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Basic rate limiting - 100 requests per minute per IP"""
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old requests
    rate_limiter[client_ip] = [req_time for req_time in rate_limiter[client_ip] 
                              if current_time - req_time < 60]
    
    if len(rate_limiter[client_ip]) >= 100:
        return JSONResponse(
            status_code=429,
            content={"detail": "🚨 Whoa there! Slow down, speed demon! Rate limit exceeded."}
        )
    
    rate_limiter[client_ip].append(current_time)
    response = await call_next(request)
    return response

# Pydantic Models
class IOCInput(BaseModel):
    ioc_value: str = Field(..., description="The IOC value to analyze")
    ioc_type: str = Field(..., description="Type of IOC (filename, sha256, command-line, etc.)")
    source: Optional[str] = Field(None, description="Source of the intelligence")
    context: Optional[Dict[str, Any]] = Field({}, description="Additional context")
    
    @validator('ioc_type')
    def validate_ioc_type(cls, v):
        valid_types = ['filename', 'sha256', 'md5', 'sha1', 'ip', 'domain', 'url', 'command-line', 'registry', 'mutex']
        if v.lower() not in valid_types:
            raise ValueError(f"IOC type must be one of: {', '.join(valid_types)}")
        return v.lower()

class BulkIOCInput(BaseModel):
    iocs: List[IOCInput] = Field(..., description="List of IOCs to process", max_items=1000)
    min_confidence: Optional[float] = Field(70.0, description="Minimum confidence threshold", ge=0, le=100)
    parallel_processing: Optional[bool] = Field(True, description="Enable parallel processing")
    
class TTPMappingResponse(BaseModel):
    id: str = Field(..., description="Unique mapping ID")
    mitre_id: str
    technique_name: str
    sub_technique: Optional[str] = None
    ioc_type: str
    ioc_value: str
    confidence_score: float
    threat_actors: List[str]
    campaigns: List[str]
    malware_families: List[str]
    kill_chain_phase: str
    detection_methods: List[str]
    false_positive_rate: float
    context: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    prevalence_score: float
    severity: str
    tags: List[str]
    
class AnalysisRequest(BaseModel):
    intelligence_data: List[Dict] = Field(..., description="Raw intelligence data")
    analysis_type: str = Field("comprehensive", description="Type of analysis")
    confidence_threshold: float = Field(70.0, description="Confidence threshold", ge=0, le=100)
    include_context: bool = Field(True, description="Include contextual information")
    generate_graph: bool = Field(False, description="Generate relationship graph")
    
class DetectionRuleRequest(BaseModel):
    mitre_techniques: List[str] = Field(..., description="MITRE techniques")
    rule_format: str = Field("sigma", description="Detection rule format")
    severity: str = Field("medium", description="Rule severity level")
    target_platform: Optional[str] = Field("windows", description="Target platform")
    include_metadata: bool = Field(True, description="Include rule metadata")
    
    @validator('rule_format')
    def validate_rule_format(cls, v):
        valid_formats = ['sigma', 'splunk', 'elastic', 'yara', 'suricata', 'snort']
        if v.lower() not in valid_formats:
            raise ValueError(f"Rule format must be one of: {', '.join(valid_formats)}")
        return v.lower()
    
    @validator('severity')
    def validate_severity(cls, v):
        valid_severities = ['low', 'medium', 'high', 'critical']
        if v.lower() not in valid_severities:
            raise ValueError(f"Severity must be one of: {', '.join(valid_severities)}")
        return v.lower()

class ThreatHuntingRequest(BaseModel):
    threat_actor: Optional[str] = Field(None, description="Specific threat actor")
    mitre_technique: Optional[str] = Field(None, description="Specific MITRE technique")
    time_range: str = Field("24h", description="Time range for hunting queries")
    platform: str = Field("splunk", description="SIEM platform")
    hunt_type: str = Field("behavioral", description="Type of hunt")
    
class MISPExportRequest(BaseModel):
    mappings: List[str] = Field(..., description="Mapping IDs to export")
    event_info: str = Field(..., description="MISP event information")
    threat_level: str = Field("2", description="MISP threat level")
    analysis: str = Field("1", description="MISP analysis level")
    distribution: str = Field("1", description="MISP distribution level")

class SearchRequest(BaseModel):
    query: str = Field(..., description="Search query")
    filters: Optional[Dict[str, Any]] = Field({}, description="Search filters")
    limit: int = Field(100, description="Maximum results", le=1000)
    offset: int = Field(0, description="Results offset", ge=0)
    sort_by: str = Field("confidence_score", description="Sort field")
    sort_order: str = Field("desc", description="Sort order")

# Dependency functions
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API token (placeholder for real auth)"""
    if credentials.credentials != "your-secret-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="🚨 Invalid API token! Nice try, script kiddie!"
        )
    return credentials.credentials

# Utility functions
def generate_mapping_id(ioc_value: str, mitre_id: str) -> str:
    """Generate unique mapping ID"""
    return hashlib.sha256(f"{ioc_value}:{mitre_id}:{int(time.time())}".encode()).hexdigest()[:16]

async def cache_response(key: str, data: Any, ttl: int = 300):
    """Cache response data"""
    request_cache[key] = {
        'data': data,
        'expires': time.time() + ttl
    }

async def get_cached_response(key: str) -> Optional[Any]:
    """Get cached response"""
    if key in request_cache:
        cache_entry = request_cache[key]
        if time.time() < cache_entry['expires']:
            return cache_entry['data']
        else:
            del request_cache[key]
    return None

# Core API Endpoints

@app.get("/", tags=["System"])
async def root():
    """Welcome endpoint"""
    return {
        "message": "🚀 Welcome to the CTE Intelligence API!",
        "docs": "/docs",
        "status": "ready-to-kick-ass",
        "version": "2.0.0"
    }

@app.get("/health", tags=["System"])
async def health_check():
    """Check if the CTE engine is running and healthy"""
    try:
        stats = await engine.get_intelligence_stats()
        return {
            "status": "🚀 CTE Engine is CRUSHING IT!",
            "engine_version": "2.0.0",
            "total_mappings": stats.get("total_mappings", 0),
            "cache_size": len(request_cache),
            "uptime": "Available 24/7 because we're badass",
            "last_updated": datetime.now().isoformat(),
            "memory_usage": f"{stats.get('memory_mb', 0):.2f} MB",
            "processing_speed": f"{stats.get('iocs_per_second', 0):.2f} IOCs/sec"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="🚨 Engine is having a rough day!")

@app.get("/stats", tags=["System"])
async def get_system_stats():
    """Get detailed system statistics"""
    stats = await engine.get_intelligence_stats()
    return {
        "engine_stats": stats,
        "api_stats": {
            "cache_entries": len(request_cache),
            "active_rate_limits": len(rate_limiter),
            "uptime": datetime.now().isoformat()
        }
    }

# Intelligence Analysis Endpoints

@app.post("/analyze/ioc", response_model=List[TTPMappingResponse], tags=["Intelligence Analysis"])
async def analyze_single_ioc(ioc: IOCInput):
    """🔍 Analyze a single IOC with our badass engine"""
    try:
        logger.info(f"🔍 Analyzing IOC: {ioc.ioc_type} | {ioc.ioc_value}")
        
        # Check cache first
        cache_key = f"ioc:{hashlib.md5(f'{ioc.ioc_value}:{ioc.ioc_type}'.encode()).hexdigest()}"
        cached_result = await get_cached_response(cache_key)
        if cached_result:
            logger.info("💨 Returning cached result")
            return cached_result
        
        mappings = await engine.smart_ioc_analysis(ioc.ioc_value, ioc.ioc_type, ioc.context)
        
        if not mappings:
            raise HTTPException(
                status_code=404, 
                detail=f"🤷 No high-confidence TTP mappings found for {ioc.ioc_type}: {ioc.ioc_value}"
            )
            
        # Convert to response format
        response_mappings = []
        for mapping in mappings:
            response_mappings.append(TTPMappingResponse(
                id=generate_mapping_id(mapping.ioc_value, mapping.mitre_id),
                mitre_id=mapping.mitre_id,
                technique_name=mapping.technique_name,
                sub_technique=getattr(mapping, 'sub_technique', None),
                ioc_type=mapping.ioc_type,
                ioc_value=mapping.ioc_value,
                confidence_score=mapping.confidence_score,
                threat_actors=mapping.threat_actors,
                campaigns=mapping.campaigns,
                malware_families=getattr(mapping, 'malware_families', []),
                kill_chain_phase=mapping.kill_chain_phase,
                detection_methods=mapping.detection_methods,
                false_positive_rate=mapping.false_positive_rate,
                context=mapping.context,
                first_seen=getattr(mapping, 'first_seen', datetime.now()),
                last_seen=getattr(mapping, 'last_seen', datetime.now()),
                prevalence_score=getattr(mapping, 'prevalence_score', 50.0),
                severity=getattr(mapping, 'severity', 'medium'),
                tags=getattr(mapping, 'tags', [])
            ))
        
        # Cache the result
        await cache_response(cache_key, response_mappings)
        
        logger.info(f"✅ Found {len(response_mappings)} high-confidence mappings")
        return response_mappings
        
    except Exception as e:
        logger.error(f"💥 IOC analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Analysis failed: {str(e)}")

@app.post("/analyze/bulk", tags=["Intelligence Analysis"])
async def analyze_bulk_iocs(bulk_request: BulkIOCInput, background_tasks: BackgroundTasks):
    """🚀 Bulk IOC analysis with parallel processing"""
    try:
        logger.info(f"🚀 Starting bulk analysis of {len(bulk_request.iocs)} IOCs")
        
        if bulk_request.parallel_processing:
            # Process in parallel batches
            batch_size = 50
            all_results = []
            
            for i in range(0, len(bulk_request.iocs), batch_size):
                batch = bulk_request.iocs[i:i + batch_size]
                batch_tasks = [
                    engine.smart_ioc_analysis(ioc.ioc_value, ioc.ioc_type, ioc.context)
                    for ioc in batch
                ]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for ioc, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        logger.warning(f"⚠️ Failed to analyze {ioc.ioc_value}: {result}")
                        continue
                    
                    if result:
                        filtered_results = [
                            mapping for mapping in result 
                            if mapping.confidence_score >= bulk_request.min_confidence
                        ]
                        all_results.extend(filtered_results)
            
            logger.info(f"✅ Bulk analysis complete: {len(all_results)} mappings found")
            return {
                "total_iocs_processed": len(bulk_request.iocs),
                "mappings_found": len(all_results),
                "processing_time": "calculated-on-demand",
                "results": all_results[:500]  # Limit response size
            }
        else:
            # Sequential processing
            all_results = []
            for ioc in bulk_request.iocs:
                try:
                    mappings = await engine.smart_ioc_analysis(ioc.ioc_value, ioc.ioc_type, ioc.context)
                    if mappings:
                        filtered_mappings = [
                            m for m in mappings 
                            if m.confidence_score >= bulk_request.min_confidence
                        ]
                        all_results.extend(filtered_mappings)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to analyze {ioc.ioc_value}: {e}")
                    continue
            
            return {
                "total_iocs_processed": len(bulk_request.iocs),
                "mappings_found": len(all_results),
                "results": all_results
            }
            
    except Exception as e:
        logger.error(f"💥 Bulk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Bulk analysis failed: {str(e)}")

@app.post("/analyze/comprehensive", tags=["Intelligence Analysis"])
async def comprehensive_analysis(analysis_request: AnalysisRequest):
    """🧠 Comprehensive intelligence analysis with relationship mapping"""
    try:
        logger.info(f"🧠 Starting comprehensive analysis of {len(analysis_request.intelligence_data)} data points")
        
        results = await engine.comprehensive_analysis(
            analysis_request.intelligence_data,
            analysis_request.analysis_type,
            analysis_request.confidence_threshold,
            analysis_request.include_context,
            analysis_request.generate_graph
        )
        
        return {
            "analysis_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "analysis_type": analysis_request.analysis_type,
            "confidence_threshold": analysis_request.confidence_threshold,
            "results": results,
            "summary": {
                "total_techniques": len(set(r.get('mitre_id', '') for r in results.get('mappings', []))),
                "total_actors": len(set(r.get('threat_actor', '') for r in results.get('actors', []))),
                "avg_confidence": sum(r.get('confidence', 0) for r in results.get('mappings', [])) / max(len(results.get('mappings', [])), 1)
            }
        }
        
    except Exception as e:
        logger.error(f"💥 Comprehensive analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Analysis failed: {str(e)}")

# Detection Rule Generation

@app.post("/generate/detection-rules", tags=["Detection Rules"])
async def generate_detection_rules(rule_request: DetectionRuleRequest):
    """🛡️ Generate detection rules from MITRE techniques"""
    try:
        logger.info(f"🛡️ Generating {rule_request.rule_format} rules for {len(rule_request.mitre_techniques)} techniques")
        
        rules = await engine.generate_detection_rules(
            rule_request.mitre_techniques,
            rule_request.rule_format,
            rule_request.severity,
            rule_request.target_platform,
            rule_request.include_metadata
        )
        
        return {
            "rule_format": rule_request.rule_format,
            "techniques_covered": rule_request.mitre_techniques,
            "severity": rule_request.severity,
            "generated_at": datetime.now().isoformat(),
            "rules": rules,
            "rule_count": len(rules)
        }
        
    except Exception as e:
        logger.error(f"💥 Rule generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Rule generation failed: {str(e)}")

# Threat Hunting

@app.post("/hunt/generate-queries", tags=["Threat Hunting"])
async def generate_hunting_queries(hunt_request: ThreatHuntingRequest):
    """🏹 Generate threat hunting queries"""
    try:
        logger.info(f"🏹 Generating hunting queries for {hunt_request.platform}")
        
        queries = await engine.generate_hunting_queries(
            hunt_request.threat_actor,
            hunt_request.mitre_technique,
            hunt_request.time_range,
            hunt_request.platform,
            hunt_request.hunt_type
        )
        
        return {
            "platform": hunt_request.platform,
            "hunt_type": hunt_request.hunt_type,
            "time_range": hunt_request.time_range,
            "generated_at": datetime.now().isoformat(),
            "queries": queries,
            "query_count": len(queries)
        }
        
    except Exception as e:
        logger.error(f"💥 Hunt query generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Hunt query generation failed: {str(e)}")

# Search and Discovery

@app.post("/search", tags=["Search"])
async def search_intelligence(search_request: SearchRequest):
    """🔍 Search intelligence database"""
    try:
        logger.info(f"🔍 Searching for: {search_request.query}")
        
        results = await engine.search_intelligence(
            search_request.query,
            search_request.filters,
            search_request.limit,
            search_request.offset,
            search_request.sort_by,
            search_request.sort_order
        )
        
        return {
            "query": search_request.query,
            "filters": search_request.filters,
            "total_results": results.get('total', 0),
            "returned_results": len(results.get('items', [])),
            "results": results.get('items', []),
            "search_time_ms": results.get('search_time_ms', 0)
        }
        
    except Exception as e:
        logger.error(f"💥 Search failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Search failed: {str(e)}")

# MISP Integration

@app.post("/export/misp", tags=["MISP Integration"])
async def export_to_misp(export_request: MISPExportRequest):
    """📤 Export mappings to MISP format"""
    try:
        logger.info(f"📤 Exporting {len(export_request.mappings)} mappings to MISP")
        
        misp_event = await engine.export_to_misp(
            export_request.mappings,
            export_request.event_info,
            export_request.threat_level,
            export_request.analysis,
            export_request.distribution
        )
        
        return {
            "export_status": "success",
            "misp_event": misp_event,
            "exported_mappings": len(export_request.mappings),
            "export_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"💥 MISP export failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 MISP export failed: {str(e)}")

# Streaming Endpoints

@app.get("/stream/live-intel", tags=["Streaming"])
async def stream_live_intelligence():
    """📡 Stream live intelligence updates"""
    async def generate_stream():
        try:
            while True:
                # Get latest intelligence updates
                updates = await engine.get_latest_updates()
                for update in updates:
                    yield f"data: {json.dumps(update)}\n\n"
                await asyncio.sleep(5)  # Update every 5 seconds
        except asyncio.CancelledError:
            logger.info("🔌 Live intelligence stream disconnected")
        except Exception as e:
            logger.error(f"💥 Stream error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        generate_stream(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )

# Export Endpoints

@app.get("/export/csv", tags=["Export"])
async def export_mappings_csv(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    min_confidence: float = Query(70.0)
):
    """📊 Export mappings to CSV"""
    try:
        mappings = await engine.get_mappings_for_export(start_date, end_date, min_confidence)
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'mitre_id', 'technique_name', 'ioc_type', 'ioc_value', 
            'confidence_score', 'threat_actors', 'campaigns'
        ])
        writer.writeheader()
        
        for mapping in mappings:
            writer.writerow({
                'mitre_id': mapping.mitre_id,
                'technique_name': mapping.technique_name,
                'ioc_type': mapping.ioc_type,
                'ioc_value': mapping.ioc_value,
                'confidence_score': mapping.confidence_score,
                'threat_actors': ', '.join(mapping.threat_actors),
                'campaigns': ', '.join(mapping.campaigns)
            })
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=cte_mappings.csv"}
        )
        
    except Exception as e:
        logger.error(f"💥 CSV export failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 CSV export failed: {str(e)}")

# Admin Endpoints

@app.post("/admin/update-intelligence", tags=["Admin"])
async def update_intelligence_database(background_tasks: BackgroundTasks):
    """🔄 Update intelligence database"""
    try:
        background_tasks.add_task(engine.update_intelligence_database)
        return {
            "status": "🔄 Intelligence database update started",
            "message": "This will run in the background like a ninja"
        }
    except Exception as e:
        logger.error(f"💥 Database update failed: {e}")
        raise HTTPException(status_code=500, detail=f"🚨 Update failed: {str(e)}")

@app.delete("/admin/clear-cache", tags=["Admin"])
async def clear_cache():
    """🧹 Clear API cache"""
    global request_cache
    cache_size = len(request_cache)
    request_cache.clear()
    return {
        "status": "✅ Cache cleared successfully",
        "cleared_entries": cache_size
    }

# Error Handlers

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            "detail": "🤷 Endpoint not found! Check the docs at /docs",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "💥 Internal server error! Our engineers are on it!",
            "timestamp": datetime.now().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting CTE Intelligence API...")
    uvicorn.run(
        "cte_api_layer:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
