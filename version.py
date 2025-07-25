#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic version management for My Network Scanner
"""

import subprocess
import os
from datetime import datetime

# Fallback version if git is not available
FALLBACK_VERSION = "1.0.4"

def is_docker_environment():
    """Check if running in Docker container"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return 'docker' in f.read() or 'containerd' in f.read()
    except:
        return False

def get_git_version():
    """Git tag'larından versiyon bilgisini al"""
    try:
        # Git tag'larını kontrol et
        result = subprocess.run(
            ['git', 'describe', '--tags', '--abbrev=0'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            tag = result.stdout.strip()
            # v prefix'ini kaldır
            if tag.startswith('v'):
                tag = tag[1:]
            return tag
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def get_git_commit_count():
    """Git commit sayısını al"""
    try:
        result = subprocess.run(
            ['git', 'rev-list', '--count', 'HEAD'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass
    
    return None

def get_git_commit_hash():
    """Git commit hash'ini al (kısa form)"""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def is_git_dirty():
    """Git working directory'sinde değişiklik var mı?"""
    try:
        result = subprocess.run(
            ['git', 'diff-index', '--quiet', 'HEAD', '--'], 
            capture_output=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        # Return code 0 means clean, 1 means dirty
        return result.returncode != 0
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return False

def get_docker_image_version():
    """Docker image'den versiyon bilgisini al"""
    try:
        # Docker image label'ından versiyon al
        result = subprocess.run([
            'docker', 'inspect', '--format', '{{index .Config.Labels "version"}}', 
            'fxerkan/my-network-scanner:latest'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
        # Alternatif olarak built-in label'ı dene
        result = subprocess.run([
            'docker', 'inspect', '--format', '{{index .Config.Labels "org.opencontainers.image.version"}}', 
            'fxerkan/my-network-scanner:latest'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def get_version():
    """Ana versiyon fonksiyonu - dinamik versiyon döndürür"""
    # Docker ortamında çalışıyorsa ve git yoksa
    if is_docker_environment():
        # Önce Docker image'den versiyon almaya çalış
        docker_version = get_docker_image_version()
        if docker_version:
            return docker_version
            
        # Git yoksa fallback kullan
        if not os.path.exists('.git'):
            return FALLBACK_VERSION
    
    git_version = get_git_version()
    
    if git_version:
        # Git tag'i varsa onu kullan
        version = git_version
        
        # Docker ortamında değilse veya git dirty değilse commit hash ekleme
        if not is_docker_environment():
            commit_hash = get_git_commit_hash()
            if commit_hash:
                version += f"-{commit_hash}"
                
            # Eğer dirty working directory varsa + ekle
            if is_git_dirty():
                version += "+"
            
        return version
    else:
        # Git tag'i yoksa commit sayısına göre minor version oluştur
        commit_count = get_git_commit_count()
        
        if commit_count is not None:
            # Commit sayısına göre otomatik versiyon oluştur
            major = 1
            minor = 0
            patch = min(commit_count, 999)  # Maksimum 999'da sınırla
            
            version = f"{major}.{minor}.{patch}"
            
            # Docker ortamında değilse commit hash ekle
            if not is_docker_environment():
                commit_hash = get_git_commit_hash()
                if commit_hash:
                    version += f"-{commit_hash}"
                    
                if is_git_dirty():
                    version += "+"
                
            return version
        else:
            # Git hiç kullanılamıyorsa fallback
            return FALLBACK_VERSION

def get_version_info():
    """Detaylı versiyon bilgisi döndürür"""
    version = get_version()
    commit_hash = get_git_commit_hash()
    commit_count = get_git_commit_count()
    is_dirty = is_git_dirty()
    
    return {
        "version": version,
        "commit_hash": commit_hash,
        "commit_count": commit_count,
        "is_dirty": is_dirty,
        "build_time": datetime.now().isoformat(),
        "git_available": commit_hash is not None
    }

# Module-level version
__version__ = get_version()

if __name__ == "__main__":
    # Test the version system
    print(f"Version: {get_version()}")
    info = get_version_info()
    print(f"Full info: {info}")