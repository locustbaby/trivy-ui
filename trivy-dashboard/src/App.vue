<template>
  <n-config-provider>
    <n-message-provider>
      <Dashboard />
    </n-message-provider>
  </n-config-provider>
</template>

<script>
import { NConfigProvider, NMessageProvider } from 'naive-ui'
import Dashboard from './views/Dashboard.vue'

export default {
  components: {
    NConfigProvider,
    NMessageProvider,
    Dashboard
  }
}
</script>

<style>
body {
  margin: 0;
  padding: 20px;
  font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
}

#app {
  max-width: 1200px;
  margin: 0 auto;
}
</style>