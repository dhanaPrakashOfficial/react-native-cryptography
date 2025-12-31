/**
 * @format
 */

import { AppRegistry } from 'react-native';
import App from './App';
import AesGcmScreen from './AesGcmScreen';
import PqcScreen from './PqcScreen';

import { name as appName } from './app.json';

// AppRegistry.registerComponent(appName, () => AesGcmScreen);
AppRegistry.registerComponent(appName, () => PqcScreen);

