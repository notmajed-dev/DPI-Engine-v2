import csv
import os
import random
import uuid

def generate_synthetic_flow_data(num_samples=1000):
    """
    Generates a synthetic but realistic labeled flow dataset.
    This simulates an auto-labeling approach where we would use the 
    engine's existing SNI extraction as ground truth labels.
    """
    app_types = [
        'YouTube', 'Netflix', 'Facebook', 'Spotify', 'DNS', 'HTTPS_Browsing', 'Zoom'
    ]
    
    data = []
    
    for _ in range(num_samples):
        app = random.choice(app_types)
        
        # Simulate different traffic patterns based on the application using random.gauss
        if app in ['YouTube', 'Netflix']:
            # Video streaming: high packet count, large packets, long duration, asymmetric bytes
            packet_count = int(random.gauss(5000, 1000))
            mean_packet_size = random.gauss(1200, 200)
            std_packet_size = random.gauss(400, 100)
            flow_duration = random.gauss(300, 100) # seconds
            bytes_ratio = random.gauss(0.05, 0.02) # Mostly downloading
        elif app == 'Zoom':
            # Video call: medium packets, long duration, symmetric bytes
            packet_count = int(random.gauss(3000, 500))
            mean_packet_size = random.gauss(600, 100)
            std_packet_size = random.gauss(200, 50)
            flow_duration = random.gauss(600, 200)
            bytes_ratio = random.gauss(1.0, 0.2) # Symmetric
        elif app == 'Spotify':
            # Audio streaming: medium packets, long duration
            packet_count = int(random.gauss(1000, 300))
            mean_packet_size = random.gauss(800, 150)
            std_packet_size = random.gauss(300, 80)
            flow_duration = random.gauss(400, 150)
            bytes_ratio = random.gauss(0.1, 0.05)
        elif app == 'DNS':
            # DNS: very few packets, small size, short duration
            packet_count = int(random.gauss(4, 1))
            mean_packet_size = random.gauss(80, 20)
            std_packet_size = random.gauss(10, 5)
            flow_duration = random.gauss(0.1, 0.05)
            bytes_ratio = random.gauss(0.5, 0.2)
        elif app == 'Facebook':
            # Social media: bursty, mixed sizes
            packet_count = int(random.gauss(500, 200))
            mean_packet_size = random.gauss(500, 200)
            std_packet_size = random.gauss(350, 100)
            flow_duration = random.gauss(120, 60)
            bytes_ratio = random.gauss(0.3, 0.1)
        else: # HTTPS_Browsing
            # General browsing: short flows, medium sizes
            packet_count = int(random.gauss(100, 50))
            mean_packet_size = random.gauss(700, 200)
            std_packet_size = random.gauss(400, 150)
            flow_duration = random.gauss(10, 5)
            bytes_ratio = random.gauss(0.2, 0.1)
            
        # Ensure non-negative values
        packet_count = max(2, packet_count)
        mean_packet_size = max(40.0, mean_packet_size)
        std_packet_size = max(0.0, std_packet_size)
        flow_duration = max(0.01, flow_duration)
        bytes_ratio = max(0.01, bytes_ratio)
        
        flow_id = str(uuid.uuid4())
        
        data.append({
            'flow_id': flow_id,
            'packet_count': packet_count,
            'mean_packet_size': mean_packet_size,
            'std_packet_size': std_packet_size,
            'flow_duration': flow_duration,
            'bytes_ratio': bytes_ratio,
            'label': app
        })
        
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    output_path = os.path.join('data', 'synthetic_flow_dataset.csv')
    
    keys = data[0].keys()
    with open(output_path, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
        
    print(f"Generated synthetic dataset at {output_path} with {len(data)} rows.")
    return data

if __name__ == "__main__":
    data = generate_synthetic_flow_data()
    print("\nFirst 10 rows of the generated dataset:")
    keys = list(data[0].keys())
    print(f"{keys[0]:<36} | {keys[1]:<12} | {keys[2]:<16} | {keys[3]:<15} | {keys[4]:<13} | {keys[5]:<11} | {keys[6]}")
    print("-" * 120)
    for row in data[:10]:
        print(f"{row['flow_id']:<36} | {row['packet_count']:<12} | {row['mean_packet_size']:<16.2f} | {row['std_packet_size']:<15.2f} | {row['flow_duration']:<13.2f} | {row['bytes_ratio']:<11.2f} | {row['label']}")
