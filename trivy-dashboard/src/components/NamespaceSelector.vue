<template>
  <div class="namespace-selector">
    <n-select
      :value="modelValue"
      :options="options"
      placeholder="Select Namespace"
      style="width: 200px; margin-right: 10px;"
      :disabled="!options.length"
      @update:value="handleNamespaceChange"
    />
  </div>
</template>

<script>
import { NSelect } from 'naive-ui'

export default {
  components: {
    NSelect
  },
  props: {
    modelValue: {
      type: String,
      default: null
    },
    options: {
      type: Array,
      default: () => []
    }
  },
  emits: ['update:modelValue'],
  methods: {
    handleNamespaceChange(value) {
      // Emit the update event with the new value
      this.$emit('update:modelValue', value)
    }
  }
}
</script>

<style scoped>
.namespace-selector {
  display: inline-block;
}
</style>