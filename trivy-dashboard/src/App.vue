<template>
  <n-config-provider>
    <n-message-provider>
      <TrivyReport />
    </n-message-provider>
  </n-config-provider>
</template>

<script>
import { NConfigProvider, NMessageProvider } from 'naive-ui'
import TrivyReport from './views/TrivyReport.vue'

export default {
  components: {
    NConfigProvider,
    NMessageProvider,
    TrivyReport
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