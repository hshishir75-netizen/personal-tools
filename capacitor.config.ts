import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.hypervault.app',
  appName: 'Hyper Vault',
  webDir: 'dist',
  server: {
    androidScheme: 'https'
  }
};

export default config;
