#!/usr/bin/env python3
# test_enhanced_capture.py
# Unit tests for the enhanced packet capture module

import os
import sys
import unittest
import tempfile
import json
import csv
import time
from unittest.mock import patch, MagicMock

# Add parent directory to path to import module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netscope.backend.enhanced_packet_capture import (
    EnhancedPacketCapture, 
    PacketProcessor, 
    OutputRotator, 
    DatabaseManager
)

class TestPacketProcessor(unittest.TestCase):
    """Test the PacketProcessor class"""
    
    def setUp(self):
        self.processor = PacketProcessor()
    
    def test_process_packet_tcp(self):
        """Test processing a TCP packet"""
        # Create a mock TCP packet
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda layer: layer in [MagicMock(), MagicMock(), MagicMock()]
        mock_packet.__getitem__.return_value = MagicMock()
        mock_packet.__len__.return_value = 100
        
        # Set up IP layer
        mock_ip = mock_packet.__getitem__.return_value
        mock_ip.src = "192.168.1.100"
        mock_ip.dst = "93.184.216.34"
        mock_ip.proto = 6  # TCP
        
        # Set up TCP layer
        mock_tcp = mock_packet.__getitem__.return_value
        mock_tcp.sport = 12345
        mock_tcp.dport = 80
        mock_tcp.flags = "SA"  # SYN-ACK
        
        # Process the packet
        result = self.processor.process_packet(mock_packet)
        
        # Verify the result
        self.assertEqual(result['src_ip'], "192.168.1.100")
        self.assertEqual(result['dst_ip'], "93.184.216.34")
        self.assertEqual(result['protocol'], "TCP")
        self.assertEqual(result['src_port'], 12345)
        self.assertEqual(result['dst_port'], 80)
        self.assertEqual(result['packet_length'], 100)
        self.assertEqual(result['tcp_flags']['SYN'], 1)
        self.assertEqual(result['tcp_flags']['ACK'], 1)
    
    def test_process_packet_udp(self):
        """Test processing a UDP packet"""
        # Create a mock UDP packet
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda layer: layer in [MagicMock(), MagicMock()]
        mock_packet.__getitem__.return_value = MagicMock()
        mock_packet.__len__.return_value = 76
        
        # Set up IP layer
        mock_ip = mock_packet.__getitem__.return_value
        mock_ip.src = "192.168.1.100"
        mock_ip.dst = "8.8.8.8"
        mock_ip.proto = 17  # UDP
        
        # Set up UDP layer
        mock_udp = mock_packet.__getitem__.return_value
        mock_udp.sport = 53612
        mock_udp.dport = 53
        
        # Process the packet
        result = self.processor.process_packet(mock_packet)
        
        # Verify the result
        self.assertEqual(result['src_ip'], "192.168.1.100")
        self.assertEqual(result['dst_ip'], "8.8.8.8")
        self.assertEqual(result['protocol'], "UDP")
        self.assertEqual(result['src_port'], 53612)
        self.assertEqual(result['dst_port'], 53)
        self.assertEqual(result['packet_length'], 76)


class TestOutputRotator(unittest.TestCase):
    """Test the OutputRotator class"""
    
    def setUp(self):
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.base_path = os.path.join(self.temp_dir, "test_packets")
        
        # Initialize the rotator with small size limit for testing
        self.rotator = OutputRotator(
            base_path=self.base_path,
            max_size_mb=0.001,  # 1KB for testing
            time_interval_sec=3600,
            formats=['json', 'csv']
        )
    
    def tearDown(self):
        # Close the rotator
        self.rotator.close()
        
        # Clean up temporary files
        for filename in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, filename))
        os.rmdir(self.temp_dir)
    
    def test_file_creation(self):
        """Test that files are created correctly"""
        # Check that files exist
        json_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.json')]
        csv_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.csv')]
        
        self.assertEqual(len(json_files), 1)
        self.assertEqual(len(csv_files), 1)
    
    def test_write_record(self):
        """Test writing a record to output files"""
        # Create a test record
        record = {
            'timestamp': '2023-06-15 14:32:45.123',
            'src_ip': '192.168.1.100',
            'dst_ip': '93.184.216.34',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_length': 74,
            'payload_length': 0,
            'tcp_flags': {
                'SYN': 1, 'ACK': 0, 'FIN': 0, 
                'RST': 0, 'PSH': 0, 'URG': 0
            }
        }
        
        # Write the record
        self.rotator.write_record(record)
        
        # Force rotation to ensure files are closed
        self.rotator._rotate_files()
        
        # Check that files contain the record
        json_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.json')]
        csv_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.csv')]
        
        # Read JSON file
        with open(os.path.join(self.temp_dir, json_files[0]), 'r') as f:
            json_data = json.load(f)
            self.assertEqual(len(json_data), 1)
            self.assertEqual(json_data[0]['src_ip'], '192.168.1.100')
            self.assertEqual(json_data[0]['dst_ip'], '93.184.216.34')
        
        # Read CSV file
        with open(os.path.join(self.temp_dir, csv_files[0]), 'r') as f:
            csv_reader = csv.reader(f)
            rows = list(csv_reader)
            self.assertEqual(len(rows), 2)  # Header + 1 record
            self.assertEqual(rows[1][1], '192.168.1.100')  # src_ip
            self.assertEqual(rows[1][2], '93.184.216.34')  # dst_ip
    
    def test_rotation_by_size(self):
        """Test file rotation based on size"""
        # Create a large record to trigger rotation
        record = {
            'timestamp': '2023-06-15 14:32:45.123',
            'src_ip': '192.168.1.100',
            'dst_ip': '93.184.216.34',
            'protocol': 'TCP',
            'packet_length': 74,
            'payload_length': 0,
            'large_field': 'x' * 1000  # Add a large field to exceed size limit
        }
        
        # Write records until rotation occurs
        initial_json_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.json')]
        
        # Write enough records to trigger rotation
        for _ in range(5):
            self.rotator.write_record(record)
        
        # Check that new files were created
        new_json_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.json')]
        self.assertGreater(len(new_json_files), len(initial_json_files))


class TestDatabaseManager(unittest.TestCase):
    """Test the DatabaseManager class"""
    
    def setUp(self):
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.db_manager = DatabaseManager(self.db_path)
    
    def tearDown(self):
        # Close the database manager
        self.db_manager.close()
        
        # Clean up temporary database
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_add_packet(self):
        """Test adding a packet to the database"""
        # Create a test packet
        packet_data = {
            'timestamp': '2023-06-15 14:32:45.123',
            'src_ip': '192.168.1.100',
            'dst_ip': '93.184.216.34',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_length': 74,
            'payload_length': 0,
            'tcp_flags': {
                'SYN': 1, 'ACK': 0, 'FIN': 0, 
                'RST': 0, 'PSH': 0, 'URG': 0
            }
        }
        
        # Add the packet
        self.db_manager.add_packet(packet_data)
        
        # Flush the batch
        self.db_manager.flush_batch()
        
        # Query the database to verify
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packets")
        rows = cursor.fetchall()
        conn.close()
        
        # Verify the result
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], '2023-06-15 14:32:45.123')  # timestamp
        self.assertEqual(rows[0][2], '192.168.1.100')  # src_ip
        self.assertEqual(rows[0][3], '93.184.216.34')  # dst_ip
        self.assertEqual(rows[0][4], 'TCP')  # protocol


@patch('netscope.backend.enhanced_packet_capture.sniff')
class TestEnhancedPacketCapture(unittest.TestCase):
    """Test the EnhancedPacketCapture class"""
    
    def setUp(self):
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.db_fd, self.db_path = tempfile.mkstemp()
        
        # Create test configuration
        self.config = {
            'interfaces': ['eth0'],
            'bpf_filter': 'tcp port 80',
            'max_packets': 10,
            'duration': 1,
            'output_dir': self.temp_dir,
            'output_base': 'test_packets',
            'db_path': self.db_path,
            'flush_interval': 1,
            'max_file_size': 1,
            'rotation_interval': 60,
            'sample_rate': 1,
            'formats': ['json', 'csv']
        }
        
        # Initialize the capture
        self.capture = EnhancedPacketCapture(self.config)
    
    def tearDown(self):
        # Stop the capture
        if hasattr(self, 'capture'):
            self.capture.stop()
        
        # Clean up temporary files
        for filename in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, filename))
        os.rmdir(self.temp_dir)
        
        # Clean up temporary database
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_start_stop(self, mock_sniff):
        """Test starting and stopping capture"""
        # Start capture
        self.capture.start()
        
        # Verify that sniff was called
        self.assertTrue(mock_sniff.called)
        
        # Stop capture
        self.capture.stop()
        
        # Verify that output files were created
        json_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.json')]
        csv_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.csv')]
        
        self.assertGreater(len(json_files), 0)
        self.assertGreater(len(csv_files), 0)
    
    def test_packet_handler(self, mock_sniff):
        """Test packet handler"""
        # Create a mock packet
        mock_packet = MagicMock()
        
        # Call packet handler
        self.capture._packet_handler(mock_packet)
        
        # Verify that packet was added to queue
        self.assertEqual(self.capture.packet_queue.qsize(), 1)


if __name__ == '__main__':
    unittest.main()