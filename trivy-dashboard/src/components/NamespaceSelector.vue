<template>
  <div class="namespace-selector">
    <n-select
      :value="modelValue"
      :options="options"
      placeholder="Select Namespace"
      style="width: 200px; margin-right: 10px;"
      @update:value="$emit('update:modelValue', $event)"
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
  emits: ['update:modelValue']
}
</script>