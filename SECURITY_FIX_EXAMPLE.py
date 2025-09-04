#!/usr/bin/env python3
"""
Security Fix Example: Parameterized Query Implementation

This file demonstrates how to fix the SQL injection vulnerabilities
found in configurationImplGpdb.py by using parameterized queries
instead of string formatting.

ISSUE: SQL injection risk in gpMgmt/bin/gppylib/system/configurationImplGpdb.py
"""

import psycopg2
from gppylib.db import dbconn


class SecureConfigurationProvider:
    """
    Example of secure SQL query patterns for Cloudberry configuration management.
    
    This replaces the vulnerable string formatting patterns found in:
    gpMgmt/bin/gppylib/system/configurationImplGpdb.py
    """
    
    def get_segment_content_secure(self, conn, seg):
        """
        BEFORE (VULNERABLE):
        sql = "SELECT content FROM pg_catalog.gp_segment_configuration WHERE dbId = %s" % self.__toSqlIntValue(seg.getSegmentDbId())
        
        AFTER (SECURE):
        Uses parameterized query with proper data binding
        """
        sql = "SELECT content FROM pg_catalog.gp_segment_configuration WHERE dbId = %s"
        cursor = dbconn.query(conn, sql, [seg.getSegmentDbId()])
        return cursor.fetchone()[0]
    
    def add_segment_secure(self, conn, seg, backout=False):
        """
        BEFORE (VULNERABLE):
        sql = "SELECT gp_add_segment(%s::int2, %s::int2, '%s', '%s', 'n', '%s', %s, %s, %s, %s)" % (...)
        
        AFTER (SECURE):
        Uses parameterized query with type casting
        """
        sql = """
        SELECT gp_add_segment(
            %s::int2, %s::int2, %s, %s, 'n', %s, 
            %s, %s, %s, %s
        )
        """
        
        params = [
            seg.getSegmentDbId(),
            seg.getSegmentContentId(),
            'm' if backout else 'p',
            seg.getSegmentPreferredRole(),
            'd' if backout else 'u',
            seg.getSegmentPort(),
            seg.getSegmentHostName(),
            seg.getSegmentAddress(),
            seg.getSegmentDataDirectory()
        ]
        
        cursor = dbconn.query(conn, sql, params)
        return cursor.fetchone()
    
    def remove_segment_mirror_secure(self, conn, seg):
        """
        BEFORE (VULNERABLE):
        sql = "SELECT gp_remove_segment_mirror(%s::int2)" % (self.__toSqlIntValue(seg.getSegmentContentId()))
        
        AFTER (SECURE):
        Parameterized query with type casting
        """
        sql = "SELECT gp_remove_segment_mirror(%s::int2)"
        cursor = dbconn.query(conn, sql, [seg.getSegmentContentId()])
        return cursor.fetchone()
    
    def insert_config_history_secure(self, conn, dbid, description):
        """
        BEFORE (VULNERABLE):
        sql = "INSERT INTO gp_configuration_history (time, dbid, \"desc\") VALUES(now(), %s, %s)" % (...)
        
        AFTER (SECURE):
        Fully parameterized insert statement
        """
        sql = """
        INSERT INTO gp_configuration_history (time, dbid, "desc") 
        VALUES (now(), %s, %s)
        """
        
        dbconn.executeUpdateOrInsert(conn, sql, [dbid, description], 1)


class InputValidation:
    """
    Enhanced input validation for database operations
    """
    
    @staticmethod
    def validate_db_id(dbid):
        """Validate database ID is a positive integer"""
        if not isinstance(dbid, int) or dbid <= 0:
            raise ValueError(f"Invalid database ID: {dbid}")
        return dbid
    
    @staticmethod
    def validate_hostname(hostname):
        """Validate hostname format"""
        if not hostname or not isinstance(hostname, str):
            raise ValueError(f"Invalid hostname: {hostname}")
        
        # Basic hostname validation (extend as needed)
        if len(hostname) > 253 or '..' in hostname:
            raise ValueError(f"Invalid hostname format: {hostname}")
        
        return hostname
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
        return port
    
    @staticmethod
    def validate_directory_path(path):
        """Validate directory path"""
        if not path or not isinstance(path, str):
            raise ValueError(f"Invalid directory path: {path}")
        
        # Basic path validation (extend as needed)
        if '..' in path or path.startswith('/'):
            raise ValueError(f"Potentially unsafe directory path: {path}")
        
        return path


# Example usage demonstrating secure patterns
def example_secure_usage():
    """
    Example of how to use the secure configuration provider
    """
    try:
        # Connect to database (using existing dbconn module)
        conn = dbconn.connect(dbconn.DbURL(port=5432, dbname='template1'))
        
        # Create secure provider
        provider = SecureConfigurationProvider()
        validator = InputValidation()
        
        # Example segment data (normally from Segment object)
        class MockSegment:
            def getSegmentDbId(self):
                return validator.validate_db_id(123)
            
            def getSegmentContentId(self):
                return validator.validate_db_id(456)
            
            def getSegmentHostName(self):
                return validator.validate_hostname("host1.example.com")
            
            def getSegmentPort(self):
                return validator.validate_port(5432)
            
            def getSegmentDataDirectory(self):
                return validator.validate_directory_path("/data/primary/gpseg0")
            
            def getSegmentPreferredRole(self):
                return "p"  # primary
        
        seg = MockSegment()
        
        # Use secure methods
        content_id = provider.get_segment_content_secure(conn, seg)
        print(f"Content ID: {content_id}")
        
        # Add segment securely
        result = provider.add_segment_secure(conn, seg)
        print(f"Add segment result: {result}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()


if __name__ == "__main__":
    # This is a demonstration/template file
    print("Security Fix Example: Parameterized Queries for Apache Cloudberry")
    print("This file shows secure alternatives to the vulnerable SQL patterns.")
    print("Apply these patterns to gpMgmt/bin/gppylib/system/configurationImplGpdb.py")