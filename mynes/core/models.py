#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Device Model - Ortak JSON schema ve data model
Normal Tarama ve Gelişmiş Analiz için birleşik veri yapısı
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class UnifiedDeviceModel:
    """
    Unified Device Model - Tüm scan metodları için ortak veri modeli
    """
    
    def __init__(self):
        self.unified_schema = {
            # Core device information
            "ip": "",
            "mac": "",
            "hostname": "",
            "vendor": "",
            "device_type": "",
            "status": "online",  # online, offline
            "last_seen": "",
            
            # User-defined information
            "alias": "",
            "notes": "",
            
            # Unified port structure
            "open_ports": [],
            
            # Unified analysis data container
            "analysis_data": {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            },
            
            # Backward compatibility fields
            "enhanced_info": None,
            "enhanced_comprehensive_info": None,
            "advanced_scan_summary": None,
            "last_enhanced_analysis": None
        }
    
    def create_unified_device(self, ip: str, mac: str, **kwargs) -> Dict[str, Any]:
        """Unified device object oluştur"""
        device = self.unified_schema.copy()
        device.update({
            "ip": ip,
            "mac": mac,
            "last_seen": datetime.now().isoformat(),
            "analysis_data": {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            }
        })
        
        # Ek parametreleri ekle
        for key, value in kwargs.items():
            if key in device:
                device[key] = value
        
        return device
    
    def create_unified_port(self, port: int, **kwargs) -> Dict[str, Any]:
        """Unified port object oluştur"""
        port_obj = {
            "port": port,
            "service": kwargs.get("service", "unknown"),
            "state": kwargs.get("state", "open"),
            "version": kwargs.get("version", ""),
            "product": kwargs.get("product", ""),
            "description": kwargs.get("description", ""),
            "manual": kwargs.get("manual", False),
            "source": kwargs.get("source", "port_scan"),  # normal_scan, enhanced_analysis, manual
            "last_verified": datetime.now().isoformat()
        }
        return port_obj
    
    def merge_device_data(self, existing_device: Dict[str, Any], new_device: Dict[str, Any], 
                         scan_type: str = "normal_scan") -> Dict[str, Any]:
        """
        Mevcut cihaz verileri ile yeni tarama sonuçlarını birleştir
        scan_type: "normal_scan" or "enhanced_analysis"
        """
        if not existing_device:
            return new_device
        
        # MAC+IP kombinasyonu kontrol et
        existing_mac = existing_device.get('mac', '').lower()
        new_mac = new_device.get('mac', '').lower()
        existing_ip = existing_device.get('ip', '')
        new_ip = new_device.get('ip', '')
        
        # MAC+IP kombinasyonu aynı olmalı merge için
        if existing_mac != new_mac or existing_ip != new_ip:
            print(f"⚠️ MAC+IP mismatch: {existing_mac}@{existing_ip} != {new_mac}@{new_ip} - farklı cihazlar, merge edilmiyor")
            return new_device
        
        print(f"🔄 MAC+IP match: {existing_mac}@{existing_ip} - merging data")
        
        # Temel bilgileri güncelle
        merged = existing_device.copy()
        
        # Core fields'ı güncelle (IP ve MAC'i koruyarak)
        core_fields = ["hostname", "vendor", "status", "last_seen"]
        for field in core_fields:
            if field in new_device and new_device[field]:
                merged[field] = new_device[field]
        
        # notes are only ever written by a human, so they are always kept.
        if existing_device.get("notes"):
            merged["notes"] = existing_device["notes"]
        elif new_device.get("notes"):
            merged["notes"] = new_device["notes"]
        else:
            merged["notes"] = ""

        # alias and device_type may come from the user OR from the scanner.
        # Blindly keeping the existing value froze every wrong guess forever -
        # a Raspberry Pi typed as "Router" once stayed a router through every
        # later scan. Keep what the user set; refresh what we generated.
        for field, marker in (("alias", "alias_source"),
                              ("device_type", "device_type_source")):
            user_owned = existing_device.get(marker) == "user"
            if user_owned and existing_device.get(field):
                merged[field] = existing_device[field]
                merged[marker] = "user"
            elif new_device.get(field):
                merged[field] = new_device[field]
                merged[marker] = new_device.get(marker, "auto")
            elif existing_device.get(field):
                merged[field] = existing_device[field]
            else:
                merged[field] = ""
        
        # Analysis data'yı güncelle
        if "analysis_data" not in merged:
            merged["analysis_data"] = {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            }
        
        # Scan type'a göre analysis data'yı güncelle
        if scan_type == "normal_scan":
            merged["analysis_data"]["last_normal_scan"] = datetime.now().isoformat()
            if "analysis_data" in new_device and "normal_scan_info" in new_device["analysis_data"]:
                merged["analysis_data"]["normal_scan_info"] = new_device["analysis_data"]["normal_scan_info"]
        elif scan_type == "enhanced_analysis":
            merged["analysis_data"]["last_enhanced_analysis"] = datetime.now().isoformat()
            if "analysis_data" in new_device and "enhanced_analysis_info" in new_device["analysis_data"]:
                merged["analysis_data"]["enhanced_analysis_info"] = new_device["analysis_data"]["enhanced_analysis_info"]
        
        # Port'ları birleştir
        merged["open_ports"] = self.merge_ports(
            existing_device.get("open_ports", []),
            new_device.get("open_ports", []),
            scan_type
        )
        
        # Encrypted credentials'ları koru (çok önemli!)
        if "encrypted_credentials" in existing_device:
            merged["encrypted_credentials"] = existing_device["encrypted_credentials"]
        
        return merged
    
    def merge_ports(self, existing_ports: List[Dict], new_ports: List[Dict], 
                   scan_type: str) -> List[Dict]:
        """Port listelerini birleştir"""
        merged_ports = {}
        
        # Mevcut port'ları ekle
        for port in existing_ports:
            port_num = port.get("port")
            if port_num:
                merged_ports[port_num] = port.copy()
        
        # Yeni port'ları ekle/güncelle
        for port in new_ports:
            port_num = port.get("port")
            if port_num:
                if port_num in merged_ports:
                    # Mevcut port'u güncelle
                    existing_port = merged_ports[port_num]
                    
                    # Manuel port'ları koru
                    if existing_port.get("manual", False):
                        continue
                    
                    # Daha detaylı bilgiyi koru
                    if port.get("version") and not existing_port.get("version"):
                        existing_port["version"] = port["version"]
                    if port.get("product") and not existing_port.get("product"):
                        existing_port["product"] = port["product"]
                    if port.get("description") and not existing_port.get("description"):
                        existing_port["description"] = port["description"]
                    
                    # Source'u güncelle
                    existing_port["source"] = port.get("source", scan_type)
                    existing_port["last_verified"] = datetime.now().isoformat()
                else:
                    # Yeni port ekle
                    new_port = port.copy()
                    new_port["source"] = port.get("source", scan_type)
                    new_port["last_verified"] = datetime.now().isoformat()
                    merged_ports[port_num] = new_port
        
        return list(merged_ports.values())
    
    def migrate_legacy_data(self, legacy_device: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy format'tan unified format'a geçiş"""
        unified_device = self.create_unified_device(
            legacy_device.get("ip", ""),
            legacy_device.get("mac", "")
        )
        
        # Temel bilgileri kopyala
        basic_fields = ["hostname", "vendor", "device_type", "status", "last_seen", "alias", "notes"]
        for field in basic_fields:
            if field in legacy_device:
                unified_device[field] = legacy_device[field]

        # Discovery sweep verisi (BLE/Zigbee radyo cihazları buna dayanır) ve
        # radyo-only işareti rescan'de kaybolmasın diye taşınır.
        for field in ("discovery", "discovery_only"):
            if field in legacy_device:
                unified_device[field] = legacy_device[field]
        
        # Port'ları dönüştür
        if "open_ports" in legacy_device:
            unified_ports = []
            for port in legacy_device["open_ports"]:
                unified_port = self.create_unified_port(
                    port.get("port", 0),
                    service=port.get("service", port.get("description", "unknown")),
                    state=port.get("state", "open"),
                    version=port.get("version", ""),
                    product=port.get("product", ""),
                    description=port.get("description", ""),
                    manual=port.get("manual", False),
                    source=port.get("source", "legacy")
                )
                unified_ports.append(unified_port)
            unified_device["open_ports"] = unified_ports
        
        # Legacy analysis data'yı migrate et
        analysis_data = {
            "last_normal_scan": None,
            "last_enhanced_analysis": None,
            "normal_scan_info": {},
            "enhanced_analysis_info": {}
        }
        
        # Enhanced info'yu migrate et
        if "enhanced_info" in legacy_device and legacy_device["enhanced_info"]:
            analysis_data["normal_scan_info"] = legacy_device["enhanced_info"]
            analysis_data["last_normal_scan"] = legacy_device.get("last_seen")
        
        # Enhanced comprehensive info'yu migrate et
        if "enhanced_comprehensive_info" in legacy_device and legacy_device["enhanced_comprehensive_info"]:
            analysis_data["enhanced_analysis_info"] = legacy_device["enhanced_comprehensive_info"]
            analysis_data["last_enhanced_analysis"] = legacy_device.get("last_enhanced_analysis")
        
        # Advanced scan summary'yi migrate et
        if "advanced_scan_summary" in legacy_device and legacy_device["advanced_scan_summary"]:
            if not analysis_data["enhanced_analysis_info"]:
                analysis_data["enhanced_analysis_info"] = legacy_device["advanced_scan_summary"]
        
        unified_device["analysis_data"] = analysis_data
        
        # Backward compatibility için legacy field'ları koru
        unified_device["enhanced_info"] = legacy_device.get("enhanced_info")
        unified_device["enhanced_comprehensive_info"] = legacy_device.get("enhanced_comprehensive_info")
        unified_device["advanced_scan_summary"] = legacy_device.get("advanced_scan_summary")
        unified_device["last_enhanced_analysis"] = legacy_device.get("last_enhanced_analysis")
        
        return unified_device
    
    def validate_device_schema(self, device: Dict[str, Any]) -> bool:
        """Device schema'sını validate et"""
        required_fields = ["ip", "mac", "hostname", "vendor", "device_type", "open_ports", "analysis_data"]
        
        for field in required_fields:
            if field not in device:
                return False
        
        # Analysis data structure kontrolü
        if "analysis_data" in device:
            analysis_data = device["analysis_data"]
            required_analysis_fields = ["last_normal_scan", "last_enhanced_analysis", 
                                      "normal_scan_info", "enhanced_analysis_info"]
            for field in required_analysis_fields:
                if field not in analysis_data:
                    return False
        
        return True
    
    def get_device_summary(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Device özet bilgilerini döndür"""
        summary = {
            "ip": device.get("ip"),
            "alias": device.get("alias", ""),
            "device_type": device.get("device_type", ""),
            "port_count": len(device.get("open_ports", [])),
            "last_seen": device.get("last_seen"),
            "status": device.get("status", "offline"),
            "has_normal_scan": False,
            "has_enhanced_analysis": False
        }
        
        if "analysis_data" in device:
            analysis_data = device["analysis_data"]
            summary["has_normal_scan"] = bool(analysis_data.get("last_normal_scan"))
            summary["has_enhanced_analysis"] = bool(analysis_data.get("last_enhanced_analysis"))
            summary["last_normal_scan"] = analysis_data.get("last_normal_scan")
            summary["last_enhanced_analysis"] = analysis_data.get("last_enhanced_analysis")
        
        return summary

# Global instance
unified_model = UnifiedDeviceModel()