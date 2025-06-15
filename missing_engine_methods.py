#!/usr/bin/env python3
"""
Additional methods needed in SmartTTPEngine to support the complete API
Add these to the existing custom_ttp_engine.py file
"""

async def initialize(self):
    """Initialize the TTP engine - called by API startup"""
    logger.info("🚀 Initializing TTP Engine...")
    # Any initialization logic here
    self.setup_database()
    self.load_pattern_library()
    logger.info("✅ TTP Engine initialized successfully")

async def comprehensive_analysis(self, intelligence_data, analysis_type, confidence_threshold, include_context, generate_graph):
    """Comprehensive intelligence analysis with relationship mapping"""
    mappings = await self.bulk_process_intelligence(intelligence_data)
    
    # Filter by confidence threshold
    high_confidence_mappings = [
        m for m in mappings 
        if m.confidence_score >= confidence_threshold
    ]
    
    results = {
        'mappings': [asdict(m) for m in high_confidence_mappings],
        'actors': list(set(actor for m in high_confidence_mappings for actor in m.threat_actors)),
        'techniques': list(set(m.mitre_id for m in high_confidence_mappings)),
        'analysis_metadata': {
            'total_processed': len(intelligence_data),
            'high_confidence_found': len(high_confidence_mappings),
            'analysis_type': analysis_type
        }
    }
    
    if generate_graph:
        results['relationship_graph'] = self._generate_relationship_graph(high_confidence_mappings)
    
    return results

async def generate_detection_rules(self, mitre_techniques, rule_format, severity, target_platform, include_metadata):
    """Generate detection rules from MITRE techniques"""
    rules = []
    
    for technique in mitre_techniques:
        if technique in self.ttp_patterns:
            pattern_config = self.ttp_patterns[technique]
            
            if rule_format == 'sigma':
                rule = self._generate_sigma_rule(technique, pattern_config, severity, target_platform)
            elif rule_format == 'splunk':
                rule = self._generate_splunk_rule(technique, pattern_config, severity)
            elif rule_format == 'elastic':
                rule = self._generate_elastic_rule(technique, pattern_config, severity)
            else:
                rule = self._generate_generic_rule(technique, pattern_config, rule_format, severity)
            
            if include_metadata:
                rule['metadata'] = {
                    'mitre_technique': technique,
                    'technique_name': pattern_config['name'],
                    'kill_chain_phase': pattern_config['kill_chain'],
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'CTE Engine v2.0'
                }
            
            rules.append(rule)
    
    return rules

async def generate_hunting_queries(self, threat_actor, mitre_technique, time_range, platform, hunt_type):
    """Generate threat hunting queries"""
    queries = []
    
    # Base query templates by platform
    query_templates = {
        'splunk': {
            'behavioral': 'index=* earliest=-{time_range} | search {search_terms} | stats count by host, user, process',
            'ioc': 'index=* earliest=-{time_range} ({ioc_terms}) | table _time, host, process, command'
        },
        'elastic': {
            'behavioral': '{{"query": {{"bool": {{"must": [{search_clauses}], "range": {{"@timestamp": {{"gte": "now-{time_range}"}}}}}}}}}',
            'ioc': '{{"query": {{"bool": {{"should": [{ioc_clauses}], "range": {{"@timestamp": {{"gte": "now-{time_range}"}}}}}}}}'
        }
    }
    
    # Generate queries based on technique or actor
    if mitre_technique and mitre_technique in self.ttp_patterns:
        pattern_config = self.ttp_patterns[mitre_technique]
        search_terms = ' OR '.join(f'"{pattern}"' for pattern in pattern_config['patterns'])
        
        template = query_templates.get(platform, {}).get(hunt_type, '')
        if template:
            query = template.format(
                time_range=time_range,
                search_terms=search_terms,
                ioc_terms=search_terms
            )
            queries.append({
                'name': f'Hunt for {pattern_config["name"]}',
                'technique': mitre_technique,
                'platform': platform,
                'query': query,
                'description': f'Hunt for indicators of {pattern_config["name"]} technique'
            })
    
    if threat_actor:
        # Generate actor-specific hunting queries
        actor_query = f'"{threat_actor}" OR "APT" OR "campaign"'
        template = query_templates.get(platform, {}).get('behavioral', '')
        if template:
            query = template.format(
                time_range=time_range,
                search_terms=actor_query
            )
            queries.append({
                'name': f'Hunt for {threat_actor} Activity',
                'actor': threat_actor,
                'platform': platform,
                'query': query,
                'description': f'Hunt for {threat_actor} related activities'
            })
    
    return queries

async def search_intelligence(self, query, filters, limit, offset, sort_by, sort_order):
    """Search intelligence database"""
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    # Build search query
    base_query = "SELECT * FROM ttp_mappings WHERE 1=1"
    params = []
    
    # Add text search
    if query:
        base_query += " AND (ioc_value LIKE ? OR technique_name LIKE ? OR mitre_id LIKE ?)"
        search_term = f"%{query}%"
        params.extend([search_term, search_term, search_term])
    
    # Add filters
    if filters.get('mitre_id'):
        base_query += " AND mitre_id = ?"
        params.append(filters['mitre_id'])
    
    if filters.get('ioc_type'):
        base_query += " AND ioc_type = ?"
        params.append(filters['ioc_type'])
    
    if filters.get('min_confidence'):
        base_query += " AND confidence_score >= ?"
        params.append(filters['min_confidence'])
    
    # Add sorting
    base_query += f" ORDER BY {sort_by} {sort_order.upper()}"
    
    # Add pagination
    base_query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    start_time = time.time()
    cursor.execute(base_query, params)
    results = cursor.fetchall()
    search_time_ms = (time.time() - start_time) * 1000
    
    # Get total count
    count_query = base_query.replace("SELECT *", "SELECT COUNT(*)").split(" ORDER BY")[0]
    cursor.execute(count_query, params[:-2])  # Exclude limit/offset params
    total_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Convert to dict format
    columns = ['id', 'mitre_id', 'technique_name', 'ioc_type', 'ioc_value', 
               'confidence_score', 'threat_actors', 'campaigns', 'first_seen', 
               'last_seen', 'frequency', 'kill_chain_phase', 'detection_methods',
               'false_positive_rate', 'context', 'source_reliability', 'created_at']
    
    items = []
    for row in results:
        item = dict(zip(columns, row))
        # Parse JSON fields
        item['threat_actors'] = json.loads(item['threat_actors'] or '[]')
        item['campaigns'] = json.loads(item['campaigns'] or '[]')
        item['detection_methods'] = json.loads(item['detection_methods'] or '[]')
        item['context'] = json.loads(item['context'] or '{}')
        items.append(item)
    
    return {
        'items': items,
        'total': total_count,
        'search_time_ms': round(search_time_ms, 2)
    }

async def export_to_misp(self, mapping_ids, event_info, threat_level, analysis, distribution):
    """Export mappings to MISP format"""
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    # Get mappings by IDs
    placeholders = ','.join('?' * len(mapping_ids))
    cursor.execute(f"SELECT * FROM ttp_mappings WHERE id IN ({placeholders})", mapping_ids)
    rows = cursor.fetchall()
    conn.close()
    
    misp_event = {
        'Event': {
            'info': event_info,
            'threat_level_id': threat_level,
            'analysis': analysis,
            'distribution': distribution,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': str(int(time.time())),
            'Attribute': [],
            'Galaxy': []
        }
    }
    
    for row in rows:
        # Add MITRE ATT&CK galaxy
        misp_event['Event']['Galaxy'].append({
            'type': 'mitre-attack-pattern',
            'name': 'ATT&CK Technique',
            'GalaxyCluster': [{
                'type': 'mitre-attack-pattern',
                'value': f"{row[1]} - {row[2]}",  # mitre_id - technique_name
                'description': f"Confidence: {row[5]}%"
            }]
        })
        
        # Add IOC as attribute
        misp_event['Event']['Attribute'].append({
            'type': row[3],  # ioc_type
            'value': row[4],  # ioc_value
            'category': 'Network activity',
            'to_ids': True,
            'comment': f"TTP mapping confidence: {row[5]}%"
        })
    
    return misp_event

async def get_latest_updates(self):
    """Get latest intelligence updates for streaming"""
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    # Get recent updates (last 5 minutes)
    cutoff_time = datetime.now() - timedelta(minutes=5)
    cursor.execute("""
        SELECT mitre_id, technique_name, ioc_type, ioc_value, confidence_score, created_at
        FROM ttp_mappings 
        WHERE created_at >= ? 
        ORDER BY created_at DESC LIMIT 10
    """, (cutoff_time.isoformat(),))
    
    updates = []
    for row in cursor.fetchall():
        updates.append({
            'type': 'new_mapping',
            'mitre_id': row[0],
            'technique_name': row[1],
            'ioc_type': row[2],
            'ioc_value': row[3],
            'confidence_score': row[4],
            'timestamp': row[5]
        })
    
    conn.close()
    return updates

async def get_mappings_for_export(self, start_date, end_date, min_confidence):
    """Get mappings for CSV export"""
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    query = "SELECT * FROM ttp_mappings WHERE confidence_score >= ?"
    params = [min_confidence]
    
    if start_date:
        query += " AND created_at >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND created_at <= ?"
        params.append(end_date)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to TTPMapping objects
    mappings = []
    for row in rows:
        mapping = TTPMapping(
            mitre_id=row[1], technique_name=row[2], ioc_type=row[3],
            ioc_value=row[4], confidence_score=row[5],
            threat_actors=json.loads(row[6] or '[]'),
            campaigns=json.loads(row[7] or '[]'),
            first_seen=datetime.fromisoformat(row[8]),
            last_seen=datetime.fromisoformat(row[9]),
            frequency=row[10], kill_chain_phase=row[11],
            detection_methods=json.loads(row[12] or '[]'),
            false_positive_rate=row[13],
            context=json.loads(row[14] or '{}'),
            source_reliability=row[15]
        )
        mappings.append(mapping)
    
    return mappings

async def update_intelligence_database(self):
    """Update intelligence database in background"""
    logger.info("🔄 Starting intelligence database update...")
    
    # This would typically:
    # 1. Fetch latest threat intelligence feeds
    # 2. Process new IOCs
    # 3. Update TTP mappings
    # 4. Refresh pattern library
    
    # For demo, simulate some work
    await asyncio.sleep(2)
    
    # Add some synthetic data
    test_iocs = [
        {'ioc_value': 'new_malware.exe', 'ioc_type': 'filename'},
        {'ioc_value': 'updated_threat.dll', 'ioc_type': 'filename'}
    ]
    
    new_mappings = await self.bulk_process_intelligence(test_iocs)
    self.save_mappings(new_mappings)
    
    logger.info(f"✅ Database update complete. Added {len(new_mappings)} new mappings")

def _generate_sigma_rule(self, technique, pattern_config, severity, target_platform):
    """Generate Sigma detection rule"""
    rule = {
        'title': f'Detection of {pattern_config["name"]}',
        'id': str(uuid.uuid4()),
        'status': 'test',
        'description': f'Detects {pattern_config["name"]} technique ({technique})',
        'references': [f'https://attack.mitre.org/techniques/{technique}/'],
        'author': 'CTE Intelligence Engine',
        'date': datetime.now().strftime('%Y/%m/%d'),
        'tags': [f'attack.{technique.lower()}', f'attack.{pattern_config["kill_chain"].replace("-", "_")}'],
        'logsource': {
            'category': 'process_creation' if 'process' in pattern_config.get('file_names', []) else 'file_event',
            'product': target_platform
        },
        'detection': {
            'selection': {},
            'condition': 'selection'
        },
        'fields': ['Image', 'CommandLine', 'User', 'LogonId'],
        'falsepositives': ['Unknown'],
        'level': severity
    }
    
    # Add detection patterns
    if 'patterns' in pattern_config:
        rule['detection']['selection']['CommandLine|contains'] = pattern_config['patterns']
    
    if 'file_names' in pattern_config:
        rule['detection']['selection']['Image|endswith'] = pattern_config['file_names']
    
    return rule

def _generate_splunk_rule(self, technique, pattern_config, severity):
    """Generate Splunk detection rule"""
    search_terms = ' OR '.join(f'"{pattern}"' for pattern in pattern_config.get('patterns', []))
    
    return {
        'name': f'Detection of {pattern_config["name"]}',
        'search': f'index=* ({search_terms}) | stats count by host, user, process | where count > 0',
        'description': f'Detects {pattern_config["name"]} technique ({technique})',
        'severity': severity,
        'mitre_technique': technique
    }

def _generate_relationship_graph(self, mappings):
    """Generate relationship graph data"""
    nodes = []
    edges = []
    
    # Create nodes for techniques, actors, and campaigns
    techniques = set(m.mitre_id for m in mappings)
    actors = set(actor for m in mappings for actor in m.threat_actors)
    campaigns = set(campaign for m in mappings for campaign in m.campaigns)
    
    for technique in techniques:
        nodes.append({'id': technique, 'type': 'technique', 'label': technique})
    
    for actor in actors:
        nodes.append({'id': actor, 'type': 'actor', 'label': actor})
    
    for campaign in campaigns:
        nodes.append({'id': campaign, 'type': 'campaign', 'label': campaign})
    
    # Create edges
    for mapping in mappings:
        for actor in mapping.threat_actors:
            edges.append({'source': mapping.mitre_id, 'target': actor, 'type': 'uses'})
        
        for campaign in mapping.campaigns:
            edges.append({'source': mapping.mitre_id, 'target': campaign, 'type': 'part_of'})
    
    return {'nodes': nodes, 'edges': edges}